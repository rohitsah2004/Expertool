"""Opt-in manual HTTP/1.1 interception. No history bodies or credentials are stored."""
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
import platform
import re
import secrets
import select
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
        from .passthrough import controls
        self.warnings=controls(policy)['warnings']
        if type(port) is not int or not 0<=port<=65535:raise ValueError('Invalid interception port')
        self.workspace,self.program,self.run_id=workspace,program,run_id
        self.guard=ManualGuard(PolicySource(policy,workspace,program),'intercept',run_id)
        self.guard.expected_version=revision(policy)
        self.ca=ca.validate().enforce(program,policy);self.token=token or secrets.token_urlsafe(32)
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
          permit.ips[0] if permit else None,'passthrough' if reason.startswith('passthrough') else ('intercept-tls' if permit and urlsplit(permit.url).scheme=='https' else 'intercept-http'),
          method=method,path_hash=hashlib.sha256(path.encode()).hexdigest() if path is not None else None,injected_headers=injected,source='browser')
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
        self.tunnel=None;self.header_timer=None;self.tls=False;self.connect_acknowledged=False
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
            from .passthrough import in_scope_host,excluded,authorize as authorize_passthrough
            current=self.server.guard.source.load()
            if excluded(current,authority.hostname):raise EgressDenied('Excluded host')
            if not in_scope_host(current,authority.hostname):
                permit=authorize_passthrough(self.server.guard,authority.hostname,authority.port)
                self.blind_relay(permit)
                return
            permit=self.server.guard.tls_preflight(authority.hostname,authority.port)
            context=self.server.context(permit)
            if not self.server.unchanged(permit):raise EgressDenied('Policy revoked')
            self.send_response(200,'Connection established');self.end_headers();self.wfile.flush();self.connect_acknowledged=True
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
            if not self.connect_acknowledged:self.reply(403,'CONNECT refused')
        finally:
            self.close_connection=True
            with self.server.connection_lock:self.server.connections.discard(self.connection)
            if isinstance(self.connection,ssl.SSLSocket):self.connection.close()
    def blind_relay(self,permit):
        upstream=None
        try:
            with self.server.guard.reserve(permit):
                if not self.server.unchanged(permit):raise EgressDenied('Policy revoked')
                upstream=socket.create_connection((permit.ips[0],permit.port),timeout=permit.config['timeout'])
                self.server.audit(permit,decision='allowed',reason='passthrough',method='CONNECT')
                self.send_response(200,'Connection established');self.end_headers();self.wfile.flush();self.connect_acknowledged=True
                deadline=time.monotonic()+permit.egress['tunnel_seconds'];total=0
                while self.server.unchanged(permit) and time.monotonic()<deadline:
                    readable,_,_=select.select([self.connection,upstream],[],[],.05)
                    for peer in readable:
                        data=peer.recv(min(16384,permit.egress['tunnel_bytes']-total+1))
                        if not data:return
                        total+=len(data)
                        if total>permit.egress['tunnel_bytes']:
                            self.server.audit(permit,reason='passthrough-byte-budget',method='CONNECT');return
                        target=upstream if peer is self.connection else self.connection
                        target.settimeout(min(1,max(.01,deadline-time.monotonic())));target.sendall(data)
                self.server.audit(permit,reason='passthrough-policy-revoked' if not self.server.unchanged(permit) else 'passthrough-time-budget',method='CONNECT')
        finally:
            if upstream:upstream.close()
            self.close_connection=True

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
        from .send import RequestSpec,send_guarded,SendError
        if self.server.stopping.is_set():self.reply(503,'interception stopped');return
        if not self.authenticated():return
        timer=None
        try:
            if self.request_version not in {'HTTP/1.0','HTTP/1.1'}:raise ValueError('HTTP/2 refused')
            length=self.framing()
            if self.tls:
                if not self.path.startswith('/') or self.path.startswith('//') or '#' in self.path:raise ValueError('Origin-form path required')
                host,port=self.tunnel;url=f'https://{host}:{port}'+self.path
            else:
                if urlsplit(self.path).scheme!='http':raise ValueError('Absolute HTTP URL required')
                url=self.path
            # Wire parsing is bounded before allocating a body. The shared sender
            # repeats the authoritative size/permission checks for every caller.
            config=self.server.guard.configuration(self.server.guard.source.load())
            if length>config['max_response_bytes']:raise ValueError('Body too large')
            self.connection.settimeout(config['timeout'])
            def expire():
                try:self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            timer=threading.Timer(config['timeout'],expire);timer.daemon=True;timer.start()
            body=self.rfile.read(length) if length else b'';timer.cancel()
            if len(body)!=length:raise ValueError('Incomplete body')
            result=send_guarded(self.server.guard,self.server.guard.source,
                RequestSpec(self.command,url,list(self.headers.items()),body),source='browser',
                is_active=lambda:not self.server.stopping.is_set())
            self.send_response_only(result.status)
            response_headers=http.client.HTTPMessage()
            for key,value in result.headers:response_headers[key]=value
            nominated={name.strip().lower() for name in response_headers.get('Connection','').split(',')}
            for key,value in result.headers:
                if key.lower() not in HOP|nominated|{'alt-svc'}:self.send_header(key,value)
            size=response_headers.get('Content-Length','0') if self.command=='HEAD' else str(len(result.body))
            if not re.fullmatch(r'[0-9]{1,20}',size):size='0'
            self.send_header('Content-Length',size);self.send_header('Connection','close');self.end_headers()
            if self.command!='HEAD':self.wfile.write(result.body)
            self.wfile.flush();self.close_connection=True
        except ssl.SSLCertVerificationError:self.reply(502,'upstream-certificate-error: certificate verification failed')
        except SendError as error:self.reply(error.status,error.reason)
        except (ValueError,OSError,http.client.HTTPException):
            self.server.audit(reason='manual-request-refused-or-failed',method=self.command)
            self.reply(403,'request refused or failed')
        finally:
            if timer:timer.cancel()
