"""Authenticated loopback forward proxy. HTTPS is opaque, full-origin CONNECT only."""
import base64
from dataclasses import dataclass, field
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import secrets
import select
import socket
import threading
import time
from urllib.parse import urlsplit, quote

from .egress import EgressGuard, PolicySource, EgressDenied
from .redaction import register_credentials

HOP = {'connection','proxy-connection','proxy-authorization','proxy-authenticate','keep-alive',
       'transfer-encoding','te','trailer','upgrade','host','content-length'}


@dataclass(frozen=True)
class ProxyEndpoint:
    host: str
    port: int
    token: str = field(repr=False)

    def __post_init__(self):
        if self.host!='127.0.0.1' or type(self.port) is not int or not 1<=self.port<=65535 or not isinstance(self.token,str) or len(self.token)<24:
            raise ValueError('Proxy endpoint requires loopback, a valid port and a strong in-memory token')

    @property
    def url(self):
        return f'http://127.0.0.1:{self.port}'

    @property
    def authorization(self):
        return 'Basic '+base64.b64encode(('expertool:'+self.token).encode()).decode()

    def environment(self):
        # Called only when building a child environment; never store this URL.
        url=f'http://expertool:{quote(self.token,safe="")}@127.0.0.1:{self.port}'
        return {key:url for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')} | {'NO_PROXY':'','no_proxy':''}


class ProxyServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=False
    request_queue_size=16

    def __init__(self,workspace,program,tool='http',run_id=None,port=0,token=None,headers_supported=False,credential_origin=None):
        policy=workspace.policy(program)
        self.guard=EgressGuard(PolicySource(policy,workspace,program),tool,run_id)
        self.headers_supported=headers_supported
        self.credential_origin=credential_origin
        self.ingress=threading.BoundedSemaphore(16)
        self.stopping=threading.Event()
        super().__init__(('127.0.0.1',port),ProxyHandler)
        self.endpoint=ProxyEndpoint('127.0.0.1',self.server_port,token or secrets.token_urlsafe(32))
        register_credentials({'Proxy-Authorization':self.endpoint.authorization})
        register_credentials({'Authorization':self.endpoint.token})
        self.thread=None

    def verify_request(self,request,client_address):
        if self.ingress.acquire(blocking=False):
            return True
        self.guard.audit(reason='ingress-concurrency-limit')
        request.sendall(b'HTTP/1.0 503 Busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
        return False

    def process_request_thread(self,request,client_address):
        try:
            super().process_request_thread(request,client_address)
        finally:
            self.ingress.release()

    def handle_error(self,request,client_address):
        self.guard.audit(reason='proxy-handler-failed')

    def __enter__(self):
        self.thread=threading.Thread(target=self.serve_forever,daemon=True)
        self.thread.start()
        return self

    def __exit__(self,*args):
        self.stopping.set()
        self.shutdown()
        self.server_close()
        if self.thread:self.thread.join(timeout=2)


class BoundedHeaders:
    def __init__(self,stream):self.stream=stream;self.total=0
    def readline(self,limit=-1):
        value=self.stream.readline(min(limit,8193) if limit>=0 else 8193)
        self.total+=len(value)
        if len(value)>8192 or self.total>32768:raise http.client.LineTooLong('bounded proxy headers')
        return value


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    header_timeout=3

    def setup(self):
        self.request.settimeout(self.header_timeout)
        super().setup()
        # One total deadline, not a fresh timeout for each trickled byte.
        def expire():
            try:self.request.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            self.server.guard.audit(reason='header-deadline')
        self.header_timer=threading.Timer(self.header_timeout,expire)
        self.header_timer.daemon=True;self.header_timer.start()

    def finish(self):
        self.header_timer.cancel()
        super().finish()

    def log_message(self,*args):
        pass

    def parse_request(self):
        if len(self.raw_requestline)>8192:
            self.request_version='HTTP/1.0';self.command=None
            self.send_error(414);self.server.guard.audit(reason='oversized-request-line');return False
        original=self.rfile
        try:
            self.rfile=BoundedHeaders(original)
            ok=super().parse_request()
        finally:
            self.rfile=original
            self.header_timer.cancel()
        # Always close after this admitted request; pipelined authority switches
        # cannot reuse authorization from a previous request.
        self.close_connection=True
        if not ok:
            self.server.guard.audit(reason='malformed-proxy-request')
        return ok

    def reply(self,status):
        self.send_response(status)
        if status==407:self.send_header('Proxy-Authenticate','Basic realm="Expertool"')
        self.send_header('Content-Length','0')
        self.send_header('Connection','close')
        self.end_headers()
        self.close_connection=True

    def preflight(self):
        values=self.headers.get_all('Proxy-Authorization') or []
        if len(values)!=1 or not hmac.compare_digest(values[0],self.server.endpoint.authorization):
            self.server.guard.audit(reason='proxy-auth-required')
            self.reply(407);return False
        lengths=self.headers.get_all('Content-Length') or []
        if self.headers.get_all('Transfer-Encoding') or any(v!='0' for v in lengths) or len(self.headers.get_all('Content-Length') or [])>1 or self.headers.get('Content-Length','0')!='0':
            self.server.guard.audit(reason='request-framing-denied')
            self.reply(400);return False
        return True

    def do_GET(self):self.forward()
    def do_HEAD(self):self.forward()
    def do_OPTIONS(self):self.forward()
    def do_POST(self):self.unsupported()
    def do_PUT(self):self.unsupported()
    def do_PATCH(self):self.unsupported()
    def do_DELETE(self):self.unsupported()
    def do_TRACE(self):self.unsupported()

    def unsupported(self):
        self.server.guard.audit(reason='method-not-permitted')
        self.reply(405)

    def forward(self):
        if not self.preflight():return
        guard=self.server.guard
        permit=None
        connection=None
        timer=None
        stop=threading.Event()
        try:
            parsed=urlsplit(self.path)
            if parsed.scheme!='http' or parsed.username or parsed.password or parsed.fragment:
                raise EgressDenied('Only absolute HTTP requests are accepted')
            host_header=urlsplit('http://'+self.headers.get('Host',''))
            if len(self.headers.get_all('Host') or [])!=1 or host_header.hostname!=parsed.hostname or (host_header.port or 80)!=(parsed.port or 80) or host_header.username or host_header.password or host_header.path or host_header.query or host_header.fragment:
                raise EgressDenied('Host authority mismatch')
            permit=guard.authorize(self.path)
            origin=f'http://{parsed.netloc}'
            if (self.headers.get('Authorization') or self.headers.get('Cookie')) and origin!=self.server.credential_origin:
                raise EgressDenied('Credentials require an exact session origin')
            with guard.reserve(permit):
                if not guard.unchanged(permit):raise EgressDenied('Policy changed')
                guard.audit(permit,decision='allowed',reason='authorized',transport='http')
                connection=http.client.HTTPConnection(permit.host,permit.port,timeout=permit.config['timeout'])
                connection.sock=socket.create_connection((permit.ips[0],permit.port),timeout=permit.config['timeout'])
                transport=connection.sock
                def terminate():
                    try:transport.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                timer=threading.Timer(permit.config['timeout'],terminate);timer.daemon=True;timer.start()
                def watch():
                    while not stop.wait(.1):
                        try:revoked=not guard.unchanged(permit)
                        except Exception:revoked=True
                        if revoked or self.server.stopping.is_set():
                            terminate();break
                threading.Thread(target=watch,daemon=True).start()
                nominated={name.strip().lower() for name in self.headers.get('Connection','').split(',')}
                headers={key:value for key,value in self.headers.items() if key.lower() not in HOP|nominated}
                # Case-insensitive replacement prevents duplicate identification headers.
                forced={'user-agent':permit.config['user_agent'],**{k.lower():v for k,v in permit.config['request_headers'].items()}}
                headers={key:value for key,value in headers.items() if key.lower() not in forced}
                headers.update(forced)
                headers['Connection']='close'
                path=parsed.path or '/'
                if parsed.query:path+='?'+parsed.query
                connection.request(self.command,path,headers=headers)
                response=connection.getresponse()
                body=response.read(permit.config['max_response_bytes']+1)
                if len(body)>permit.config['max_response_bytes']:
                    raise EgressDenied('Response size budget exceeded')
                if not guard.unchanged(permit):raise EgressDenied('Policy revoked')
                self.send_response(response.status)
                for key,value in response.getheaders():
                    if key.lower() not in HOP|{'server','date'}:
                        self.send_header(key,value)
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Connection','close');self.end_headers()
                if self.command!='HEAD':self.wfile.write(body)
                response.close()
        except (ValueError,OSError,http.client.HTTPException):
            guard.audit(permit,reason='request-refused-or-failed',transport='http')
            try:self.reply(403 if permit is None else 502)
            except OSError:pass
        finally:
            stop.set()
            if timer:timer.cancel()
            if connection:connection.close()

    def do_CONNECT(self):
        if not self.preflight():return
        guard=self.server.guard
        permit=None
        upstream=None
        connected=False
        try:
            parsed=urlsplit('https://'+self.path+'/')
            if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path!='/':
                raise EgressDenied('Invalid CONNECT authority')
            if parsed.port is None or len(self.headers.get_all('Host') or [])!=1 or self.headers['Host'].lower()!=self.path.lower():
                raise EgressDenied('CONNECT needs an explicit matching host and port')
            permit=guard.authorize('https://'+self.path+'/',connect=True,headers_supported=self.server.headers_supported)
            with guard.reserve(permit):
                if not guard.unchanged(permit):raise EgressDenied('Policy changed')
                guard.audit(permit,decision='allowed',reason='authorized-connect',transport='connect')
                upstream=socket.create_connection((permit.ips[0],permit.port),timeout=permit.config['timeout'])
                self.send_response(200,'Connection established');self.end_headers();connected=True
                deadline=time.monotonic()+permit.egress['tunnel_seconds']
                total=0
                while not self.server.stopping.is_set() and time.monotonic()<deadline:
                    if not guard.unchanged(permit):
                        guard.audit(permit,reason='policy-revoked',transport='connect');break
                    readable,_,_=select.select([self.connection,upstream],[],[],.1)
                    for source in readable:
                        data=source.recv(16384)
                        if not data:return
                        total+=len(data)
                        if total>permit.egress['tunnel_bytes']:
                            guard.audit(permit,reason='tunnel-byte-budget',transport='connect');return
                        destination=upstream if source is self.connection else self.connection
                        destination.settimeout(min(1,max(.01,deadline-time.monotonic())))
                        destination.sendall(data)
                if time.monotonic()>=deadline:
                    guard.audit(permit,reason='tunnel-time-budget',transport='connect')
        except (ValueError,OSError):
            guard.audit(permit,reason='connect-refused-or-failed',transport='connect')
            if not connected:
                try:self.reply(403)
                except OSError:pass
        finally:
            if upstream:upstream.close()
            self.close_connection=True
