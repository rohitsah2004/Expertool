"""Opt-in manual HTTP/1.1 interception. No history bodies or credentials are stored."""
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
import platform
import re
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit,urlunsplit

from .egress import EgressGuard,PolicySource,EgressDenied,revision
from .local_ca import LocalCA,CAError
from .manual_policy import manual_settings,method_allowed
from .proxy import BoundedHeaders,HOP
from .redaction import register_credentials
from .scope import matches,parse_asset_rule


class ManualGuard(EgressGuard):
    def configuration(self,policy):return manual_settings(policy)
    def tls_preflight(self,host,port):
        policy=self.source.load();config=self.configuration(policy)
        # TLS is authorized for a host with at least one permitted HTTPS path.
        # No target HTTP request is made at this stage. Actual paths are checked
        # after decrypting each HTTP/1.1 request, including path exclusions.
        candidates=list(config['path_prefixes'])
        for value in policy.get('asset_scope',{}).get('include',[]):
            rule=parse_asset_rule(value)
            if rule['kind']=='url' and rule['scheme']=='https' and rule['port']==port and matches(host,rule['host']):
                candidates.append(rule['path'])
        for path in dict.fromkeys(candidates):
            try:return self.authorize(f'https://{host}:{port}{path}')
            except EgressDenied:continue
        raise EgressDenied('No permitted HTTPS path for this host')


class InterceptServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=False
    request_queue_size=16
    def __init__(self,workspace,program,run_id,ca,port=0,token=None):
        if platform.system()!='Darwin':raise ValueError('Interception is currently supported on macOS only')
        policy=workspace.policy(program);manual_settings(policy)
        if type(port) is not int or not 0<=port<=65535:raise ValueError('Invalid interception port')
        self.workspace,self.program,self.run_id=workspace,program,run_id
        self.guard=ManualGuard(PolicySource(policy,workspace,program),'intercept',run_id)
        self.guard.expected_version=revision(policy)
        self.ca=ca.validate();self.token=token or secrets.token_urlsafe(32)
        if not isinstance(self.token,str) or len(self.token)<24:raise ValueError('Interception token must be at least 24 characters')
        import base64
        self.authorization='Basic '+base64.b64encode(('expertool:'+self.token).encode()).decode()
        register_credentials({'Proxy-Authorization':self.authorization,'Authorization':self.token})
        self.stopping=threading.Event();self.revoked=threading.Event()
        self.connections=set();self.connection_lock=threading.Lock();self.ingress=threading.BoundedSemaphore(16)
        self.contexts={};self.context_lock=threading.Lock()
        self.thread=None;self.watch_thread=None;self.ca_lease=None
        super().__init__(('127.0.0.1',port),InterceptHandler)
    def verify_request(self,request,address):
        if self.stopping.is_set() or not self.ingress.acquire(blocking=False):
            request.close();return False
        with self.connection_lock:self.connections.add(request)
        return True
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:
            with self.connection_lock:self.connections.discard(request)
            self.ingress.release()
    def handle_error(self,request,address):
        self.audit(reason='interception-handler-failed')
    def audit(self,permit=None,decision='denied',reason='interception-refused',method=None,path=None,injected=(),host=None,port=None):
        self.workspace.audit_egress(self.program,permit.host if permit else host,permit.port if permit else port,
          decision,reason,'intercept',self.run_id,permit.version if permit else self.guard.expected_version,
          permit.ips[0] if permit else None,'intercept-tls' if permit and urlsplit(permit.url).scheme=='https' else 'intercept-http',
          method=method,path_hash=hashlib.sha256(path.encode()).hexdigest() if path is not None else None,injected_headers=injected)
    def close_connections(self):
        with self.connection_lock:clients=list(self.connections)
        for client in clients:
            try:client.shutdown(socket.SHUT_RDWR)
            except OSError:pass
    def unchanged(self,permit):
        return not self.stopping.is_set() and self.guard.unchanged(permit)
    def context(self,permit):
        key=(permit.host,permit.version)
        with self.context_lock:
            if key not in self.contexts:
                if len(self.contexts)>=64:raise CAError('Per-run TLS context budget exhausted')
                self.contexts[key]=self.ca.server_context(permit,self.guard)
            if not self.unchanged(permit):raise EgressDenied('Policy revoked')
            return self.contexts[key]
    def __enter__(self):
        self.ca_lease=self.ca.lease();self.ca_lease.__enter__()
        self.thread=threading.Thread(target=self.serve_forever,daemon=True);self.thread.start()
        def watch():
            while not self.stopping.wait(.1):
                try:
                    current=self.guard.source.load();config=self.guard.configuration(current)
                    invalid=revision(current)!=self.guard.expected_version or time.monotonic()-self.guard.started>=config['max_seconds']
                except Exception:invalid=True
                if invalid:
                    self.revoked.set();self.audit(reason='interception-policy-revoked');self.stopping.set();self.close_connections();break
        self.watch_thread=threading.Thread(target=watch,daemon=True);self.watch_thread.start()
        return self
    def stop(self):self.stopping.set();self.close_connections()
    def __exit__(self,*args):
        self.stop();self.shutdown();self.server_close()
        if self.thread:self.thread.join(timeout=2)
        if self.watch_thread:self.watch_thread.join(timeout=2)
        self.contexts.clear()
        if self.ca_lease:self.ca_lease.__exit__(None,None,None)


class InterceptHandler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def setup(self):
        self.tunnel=None;self.header_timer=None;self.tls=False
        self.request.settimeout(3);super().setup()
    def log_message(self,*args):pass
    def handle_one_request(self):
        def expire():
            try:self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.header_timer=threading.Timer(3,expire);self.header_timer.daemon=True;self.header_timer.start()
        try:super().handle_one_request()
        finally:self.header_timer.cancel()
    def parse_request(self):
        if len(self.raw_requestline)>8192:
            self.command=None;self.request_version='HTTP/1.0';self.send_error(414);return False
        original=self.rfile
        try:
            self.rfile=BoundedHeaders(original);ok=super().parse_request()
        finally:self.rfile=original;self.header_timer.cancel()
        if not ok:self.server.audit(reason='malformed-interception-request')
        return ok
    def finish(self):
        if self.header_timer:self.header_timer.cancel()
        super().finish()
    def reply(self,status,reason):
        body=('Expertool: '+reason+'\n').encode()
        try:
            self.send_response(status)
            if status==407:self.send_header('Proxy-Authenticate','Basic realm="Expertool manual interception"')
            self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close')
            self.end_headers();self.wfile.write(body);self.wfile.flush()
        except OSError:pass
        self.close_connection=True
    def authenticated(self):
        if self.tls:return True
        values=self.headers.get_all('Proxy-Authorization') or []
        if len(values)!=1 or not hmac.compare_digest(values[0],self.server.authorization):
            self.server.audit(reason='interception-auth-required');self.reply(407,'proxy authentication required');return False
        return True
    def framing(self):
        names=[name.lower() for name in self.headers.keys()]
        if len(names)!=len(set(names)) or self.headers.get_all('Transfer-Encoding') or self.headers.get('Expect'):
            raise ValueError('Ambiguous framing')
        value=self.headers.get('Content-Length','0')
        if not re.fullmatch(r'0|[1-9][0-9]{0,8}',value):raise ValueError('Invalid length')
        return int(value)
    def do_CONNECT(self):
        if self.tls:self.reply(405,'nested CONNECT refused');return
        if not self.authenticated():return
        try:
            if self.framing()!=0:raise ValueError('CONNECT body forbidden')
            authority=urlsplit('https://'+self.path)
            if not authority.hostname or authority.username or authority.password or authority.path or authority.query or authority.fragment or authority.port is None:
                raise ValueError('Invalid CONNECT authority')
            if self.headers.get('Host','').lower()!=self.path.lower():raise ValueError('Host mismatch')
            permit=self.server.guard.tls_preflight(authority.hostname,authority.port)
            context=self.server.context(permit)
            if not self.server.unchanged(permit):raise EgressDenied('Policy revoked')
            self.send_response(200,'Connection established');self.end_headers();self.wfile.flush()
            old=self.connection
            with self.server.connection_lock:
                secured=context.wrap_socket(old,server_side=True,do_handshake_on_connect=False)
                self.server.connections.discard(old);self.server.connections.add(secured)
            self.connection=secured;self.request=secured
            self.connection.settimeout(3);self.connection.do_handshake()
            if self.connection.selected_alpn_protocol() not in {None,'http/1.1'}:raise ValueError('HTTP/2 not supported')
            self.rfile.close();self.wfile.close()
            self.rfile=self.connection.makefile('rb',self.rbufsize);self.wfile=self.connection.makefile('wb',0)
            self.tls=True;self.tunnel=(permit.host,permit.port)
            self.server.audit(permit,decision='allowed',reason='interception-tls-established',method='CONNECT')
            # Each decrypted request gets a new policy, DNS permit and shared budget.
            for _ in range(permit.config['max_requests']):
                self.close_connection=True
                self.handle_one_request()
                if self.close_connection or self.server.stopping.is_set():break
        except ssl.SSLError:
            self.server.audit(reason='interception-client-tls-error',method='CONNECT');self.close_connection=True
        except (ValueError,OSError,CAError):
            self.server.audit(reason='interception-connect-refused',method='CONNECT')
            if not self.tls:self.reply(403,'CONNECT refused')
        finally:
            self.close_connection=True
            with self.server.connection_lock:self.server.connections.discard(self.connection)
            if self.tls:self.connection.close()
    def do_GET(self):self.forward()
    def do_HEAD(self):self.forward()
    def do_OPTIONS(self):self.forward()
    def do_POST(self):
        if not self.tls and self.path=='/__expertool_stop':
            if not self.authenticated():return
            if self.headers.get('Host')!=f'127.0.0.1:{self.server.server_port}':self.reply(403,'control Host mismatch');return
            self.reply(200,'interception stopping');self.server.stop();return
        self.forward()
    def do_PUT(self):self.forward()
    def do_PATCH(self):self.forward()
    def do_DELETE(self):self.forward()
    def do_TRACE(self):self.forward()
    def forward(self):
        if self.server.stopping.is_set():self.reply(503,'interception stopped');return
        if not self.authenticated():return
        permit=None;connection=None;stop=threading.Event();timer=None;body_timer=None
        path=None;method=self.command;injected=[];host=None;port=None
        try:
            if self.request_version not in {'HTTP/1.0','HTTP/1.1'}:raise ValueError('HTTP/2 refused')
            length=self.framing()
            if self.headers.get('Upgrade') or 'upgrade' in self.headers.get('Connection','').lower():
                self.server.audit(reason='websocket-upgrade-refused',method=method);self.reply(405,'WebSocket upgrades are disabled');return
            if self.tls:
                if not self.path.startswith('/') or self.path.startswith('//') or '#' in self.path:raise ValueError('Origin-form path required')
                host,port=self.tunnel;url=f'https://{host}:{port}'+self.path
            else:
                parsed=urlsplit(self.path)
                if parsed.scheme!='http' or parsed.username or parsed.password or parsed.fragment:raise ValueError('Absolute HTTP URL required')
                url=self.path;host=parsed.hostname;port=parsed.port or 80
            parsed=urlsplit(url);path=parsed.path or '/'
            authority=urlsplit('http://'+self.headers.get('Host',''))
            if authority.hostname!=host or (authority.port or (443 if self.tls else 80))!=port or authority.username or authority.password or authority.path or authority.query or authority.fragment:
                raise ValueError('Host authority mismatch')
            current=self.server.guard.source.load()
            if not method_allowed(current,method):
                self.server.audit(reason='manual-method-denied',method=method,path=path,host=host,port=port);self.reply(405,'manual method is not enabled');return
            permit=self.server.guard.authorize(url)
            if length>permit.config['max_response_bytes']:raise ValueError('Request body budget exceeded')
            if method in {'GET','HEAD','OPTIONS'} and length:raise ValueError('Read-only request body refused')
            if (self.headers.get('Authorization') or self.headers.get('Cookie')) and not self.tls and not all(ipaddress.ip_address(ip).is_loopback for ip in permit.ips):
                raise ValueError('Credentials require verified TLS')
            register_credentials({name:self.headers[name] for name in ('Authorization','Cookie') if self.headers.get(name)})
            with self.server.guard.reserve(permit):
                self.connection.settimeout(permit.config['timeout'])
                def abort_body():
                    try:self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                body_timer=threading.Timer(permit.config['timeout'],abort_body);body_timer.daemon=True;body_timer.start()
                body=self.rfile.read(length) if length else None
                body_timer.cancel()
                if body is not None and len(body)!=length:raise ValueError('Incomplete body')
                if not self.server.unchanged(permit):raise EgressDenied('Policy revoked')
                connection=http.client.HTTPConnection(permit.host,permit.port,timeout=permit.config['timeout'])
                raw=socket.create_connection((permit.ips[0],permit.port),timeout=permit.config['timeout'])
                connection.sock=raw
                def terminate():
                    try:connection.sock.shutdown(socket.SHUT_RDWR)
                    except (OSError,AttributeError):pass
                timer=threading.Timer(permit.config['timeout'],terminate);timer.daemon=True;timer.start()
                def watch():
                    while not stop.wait(.1):
                        if self.server.stopping.is_set() or not self.server.unchanged(permit):terminate();break
                threading.Thread(target=watch,daemon=True).start()
                if self.tls:
                    verified=ssl.create_default_context();verified.set_alpn_protocols(['http/1.1'])
                    connection.sock=verified.wrap_socket(raw,server_hostname=permit.host)
                if not self.server.unchanged(permit):raise EgressDenied('Policy revoked')
                nominated={name.strip().lower() for name in self.headers.get('Connection','').split(',')}
                headers={key:value for key,value in self.headers.items() if key.lower() not in HOP|nominated|{'expect','accept-encoding'}}
                forced={'user-agent':permit.config['user_agent'],**{key.lower():value for key,value in permit.config['request_headers'].items()}}
                headers={key:value for key,value in headers.items() if key.lower() not in forced}
                headers.update(forced);headers['Accept-Encoding']='identity';headers['Connection']='close'
                injected=sorted(forced)
                self.server.audit(permit,decision='allowed',reason='manual-request-forwarded',method=method,path=path,injected=injected)
                request_path=urlunsplit(('','',parsed.path or '/',parsed.query,''))
                connection.request(method,request_path,body=body,headers=headers)
                response=connection.getresponse()
                if response.status==101:raise ValueError('Upgrade response refused')
                content=response.read(permit.config['max_response_bytes']+1)
                if len(content)>permit.config['max_response_bytes']:raise ValueError('Response budget exceeded')
                if not self.server.unchanged(permit):raise EgressDenied('Policy revoked')
                self.send_response_only(response.status)
                response_hop={name.strip().lower() for name in response.getheader('Connection','').split(',')}
                for key,value in response.getheaders():
                    if key.lower() not in HOP|response_hop|{'alt-svc'}:self.send_header(key,value)
                response_size=response.getheader('Content-Length','0') if method=='HEAD' else str(len(content))
                if not re.fullmatch(r'[0-9]{1,20}',response_size):response_size='0'
                self.send_header('Content-Length',response_size);self.send_header('Connection','close');self.end_headers()
                if method!='HEAD':self.wfile.write(content)
                self.wfile.flush();self.close_connection=True
        except ssl.SSLCertVerificationError:
            self.server.audit(permit,reason='upstream-certificate-error',method=method,path=path,injected=injected,host=host,port=port)
            self.reply(502,'upstream-certificate-error: certificate verification failed')
        except (ValueError,OSError,http.client.HTTPException):
            self.server.audit(permit,reason='manual-request-refused-or-failed',method=method,path=path,injected=injected,host=host,port=port)
            self.reply(403 if permit is None else 502,'request refused or failed')
        finally:
            stop.set()
            if timer:timer.cancel()
            if body_timer:body_timer.cancel()
            if connection:connection.close()
