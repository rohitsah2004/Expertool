"""One guarded, single-request manual send path; no retries, loops or storage of bodies."""
from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit,urlunsplit
from .egress import EgressDenied
from .manual_policy import method_allowed,READ_ONLY
from .proxy import HOP
from .redaction import register_credentials

@dataclass(frozen=True)
class RequestSpec:
    method:str
    url:str
    headers:list
    body:bytes=b''

@dataclass(frozen=True)
class ResponseSpec:
    status:int
    headers:list
    body:bytes
    timings:dict
    truncated:bool
    permit:object
    policy_version:str
    injected_headers:tuple

class SendError(ValueError):
    def __init__(self,reason='manual-request-refused-or-failed',status=403):
        super().__init__(reason);self.reason=reason;self.status=status


def send_guarded(guard,policy_source,request,*,source,is_active=lambda:True):
    if source not in {'browser','replay','manual'}:raise SendError('invalid-request-source')
    if policy_source is not guard.source:raise SendError('policy-source-mismatch')
    permit=None;connection=None;timer=None;done=threading.Event();injected=()
    started=time.monotonic();timings={}
    try:parsed=urlsplit(request.url)
    except (ValueError,TypeError):raise SendError('invalid-request-url') from None
    def audit(decision,reason):
        policy_source.audit(host=permit.host if permit else parsed.hostname,port=permit.port if permit else parsed.port,
            decision=decision,reason=reason,tool=guard.tool,run_id=guard.run_id,
            version=permit.version if permit else None,ip=permit.ips[0] if permit else None,
            transport='intercept-tls' if parsed.scheme=='https' else 'intercept-http',
            method=request.method,path_hash=hashlib.sha256((parsed.path or '/').encode()).hexdigest(),
            injected_headers=injected,source=source)
    def unchanged():return is_active() and guard.unchanged(permit)
    try:
        if not method_allowed(policy_source.load(),request.method):raise SendError('manual-method-denied',405)
        permit=guard.authorize(request.url)
        if not isinstance(request.body,bytes):raise SendError('body-must-be-bytes',502)
        if len(request.body)>permit.config['max_response_bytes']:raise SendError('request-body-budget',502)
        if request.method in READ_ONLY and request.body:raise SendError('read-only-body-refused',502)
        pairs=list(request.headers);headers={};seen=set()
        for key,value in pairs:
            if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9-]+',key) or not isinstance(value,str) or any(ord(c)<32 or ord(c)>126 for c in value):raise SendError('invalid-request-header')
            lower=key.lower()
            if lower in seen:raise SendError('duplicate-request-header')
            seen.add(lower);headers[lower]=value
        if parsed.scheme not in {'http','https'} or parsed.fragment:raise SendError('invalid-request-url')
        if 'host' in headers:
            authority=urlsplit('http://'+headers['host'])
            if authority.hostname!=parsed.hostname or (authority.port or (443 if parsed.scheme=='https' else 80))!=(parsed.port or (443 if parsed.scheme=='https' else 80)) or authority.username or authority.password or authority.path or authority.query or authority.fragment:raise SendError('host-authority-mismatch')
        if headers.get('upgrade') or 'upgrade' in headers.get('connection','').lower():raise SendError('websocket-upgrade-refused',405)
        if 'transfer-encoding' in headers or 'expect' in headers:raise SendError('ambiguous-framing')
        if 'content-length' in headers and headers['content-length']!=str(len(request.body)):raise SendError('body-length-mismatch')
        if ('authorization' in headers or 'cookie' in headers) and parsed.scheme!='https' and not all(ipaddress.ip_address(ip).is_loopback for ip in permit.ips):raise SendError('credentials-require-tls')
        register_credentials({k:v for k,v in pairs if k.lower() in {'authorization','cookie'}})
        with guard.reserve(permit):
            if not unchanged():raise SendError('policy-revoked',502)
            connection=http.client.HTTPConnection(permit.host,permit.port,timeout=permit.config['timeout'])
            connect_started=time.monotonic()
            connection.sock=socket.create_connection((permit.ips[0],permit.port),timeout=permit.config['timeout'])
            timings['connect_seconds']=time.monotonic()-connect_started
            def terminate():
                try:connection.sock.shutdown(socket.SHUT_RDWR)
                except (OSError,AttributeError):pass
            timer=threading.Timer(permit.config['timeout'],terminate);timer.daemon=True;timer.start()
            def watch():
                while not done.wait(.05):
                    if not unchanged():terminate();break
            threading.Thread(target=watch,daemon=True).start()
            if parsed.scheme=='https':
                tls_started=time.monotonic();context=ssl.create_default_context();context.set_alpn_protocols(['http/1.1'])
                connection.sock=context.wrap_socket(connection.sock,server_hostname=permit.host)
                timings['tls_seconds']=time.monotonic()-tls_started
            nominated={name.strip().lower() for name in headers.get('connection','').split(',')}
            forced={'user-agent':permit.config['user_agent'],**{key.lower():value for key,value in permit.config['request_headers'].items()}}
            outgoing=[(k,v) for k,v in pairs if k.lower() not in HOP|nominated|{'expect','accept-encoding'}|set(forced)]
            outgoing.extend(forced.items());outgoing.extend([('Accept-Encoding','identity'),('Connection','close')]);injected=tuple(sorted(forced))
            if not unchanged():raise SendError('policy-revoked',502)
            audit('allowed','manual-request-forwarded')
            path=urlunsplit(('','',parsed.path or '/',parsed.query,''))
            # putrequest/putheader preserves response/request header ordering; the
            # input RequestSpec is never rewritten. W1 duplicate requests stay refused.
            connection.putrequest(request.method,path,skip_accept_encoding=True)
            for key,value in outgoing:connection.putheader(key,value)
            if request.body or request.method not in READ_ONLY:connection.putheader('Content-Length',str(len(request.body)))
            connection.endheaders(request.body or None)
            response=connection.getresponse();timings['first_byte_seconds']=time.monotonic()-started
            if response.status==101:raise SendError('upgrade-response-refused',502)
            body=response.read(permit.config['max_response_bytes']+1)
            if len(body)>permit.config['max_response_bytes']:raise SendError('response-budget-exceeded',502)
            if not unchanged():raise SendError('policy-revoked',502)
            result=ResponseSpec(response.status,response.getheaders(),body,{**timings,'total_seconds':time.monotonic()-started},False,permit,permit.version,injected)
            audit('allowed','manual-response-completed')
            return result
    except ssl.SSLCertVerificationError:
        audit('denied','upstream-certificate-error');raise
    except SendError as error:
        audit('denied',error.reason);raise
    except (ValueError,OSError,http.client.HTTPException):
        audit('denied','manual-request-refused-or-failed')
        raise SendError(status=502 if permit else 403) from None
    finally:
        done.set()
        if timer:timer.cancel()
        if connection:connection.close()
