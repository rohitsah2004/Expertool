"""Fail-closed external process launch. macOS Seatbelt is the only verified backend."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

from .redaction import sanitize, sanitize_output

CONTEXT=ContextVar('expertool_guard_context',default=None)


class IsolationUnavailable(ValueError):
    pass


@contextmanager
def guard_context(workspace,program,tool,run_id):
    token=CONTEXT.set((workspace,program,tool,run_id))
    try:yield
    finally:CONTEXT.reset(token)


def profile(port=None):
    rules='(version 1)(allow default)(deny network*)(deny mach-lookup)'
    if port is not None:
        if type(port) is not int or not 1<=port<=65535:raise IsolationUnavailable('Invalid proxy port')
        rules+=f'(allow network-outbound (remote tcp4 "localhost:{port}"))'
    return rules


def verify_backend(endpoint=None):
    if platform.system()!='Darwin' or shutil.which('sandbox-exec') is None:
        raise IsolationUnavailable('No verified process network isolation backend on this OS')
    blocked=socket.socket();blocked.bind(('127.0.0.1',0));blocked.listen(4)
    port=blocked.getsockname()[1]
    ports=([endpoint.port] if endpoint else [])+[port]
    # A direct connection, a UDP send and a spawned child's direct connection must fail.
    script='''import socket,subprocess,sys,json
results=[]
for port in PORTS:
 try:
  sock=socket.create_connection(('127.0.0.1',port),timeout=.7);sock.close();results.append(True)
 except OSError:results.append(False)
try:
 sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.sendto(b'probe',('127.0.0.1',BLOCKED));udp=True
except OSError:udp=False
child=subprocess.run([sys.executable,'-c',"import socket; socket.create_connection(('127.0.0.1',BLOCKED),timeout=.5)"],capture_output=True)
print(json.dumps({'tcp':results,'udp':udp,'child_allowed':child.returncode==0}))
'''.replace('PORTS',repr(ports)).replace('BLOCKED',str(port))
    try:
        result=subprocess.run(['/usr/bin/sandbox-exec','-p',profile(endpoint.port if endpoint else None),sys.executable,'-c',script],
                              stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5,close_fds=True)
        expected=([True] if endpoint else [])+[False]
        if result.returncode or json.loads(result.stdout)!={'tcp':expected,'udp':False,'child_allowed':False}:
            raise IsolationUnavailable('Process network isolation self-test failed')
    except (OSError,ValueError,subprocess.TimeoutExpired) as error:
        raise IsolationUnavailable('Process network isolation could not be verified') from error
    finally:blocked.close()
    return 'macos-seatbelt-verified'


def run_guarded(arguments,timeout,max_bytes,directory,watched=(),endpoint=None,pass_fds=(),environment_overrides=None,accepted_exit_codes=(0,),include_stderr=False):
    verify_backend(endpoint)
    binary=shutil.which(arguments[0]) if not os.path.isabs(arguments[0]) else arguments[0]
    if not binary:raise FileNotFoundError('Tool not installed')
    # Do not inherit session cookies, API tokens, proxy config, shell startup options or runtime injection variables.
    environment={key:os.environ[key] for key in ('PATH','HOME','LANG','LC_ALL','SSL_CERT_FILE','SSL_CERT_DIR','SYSTEMROOT') if key in os.environ}
    environment['TMPDIR']=str(directory)
    overrides=environment_overrides or {}
    allowed={'HOME','XDG_CONFIG_HOME','XDG_CACHE_HOME','NUCLEI_CONFIG_DIR','NUCLEI_TEMPLATES_DIRECTORY','EXPERTOOL_SCANNER','EXPERTOOL_DNS_MAP','GEM_HOME','GEM_PATH'}
    if set(overrides)-allowed or any(not isinstance(v,str) for v in overrides.values()):
        raise IsolationUnavailable('Unsupported child environment override')
    environment.update(overrides)
    if endpoint:environment.update(endpoint.environment())
    command=['/usr/bin/sandbox-exec','-p',profile(endpoint.port if endpoint else None),binary,*arguments[1:]]
    process=subprocess.Popen(command,cwd=directory,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             start_new_session=True,close_fds=True,pass_fds=tuple(pass_fds))
    buffers=[bytearray(),bytearray()]
    overflow=threading.Event()
    def drain(stream,index):
        while True:
            chunk=stream.read(4096)
            if not chunk:break
            if sum(map(len,buffers))+len(chunk)>max_bytes:
                overflow.set();break
            buffers[index].extend(chunk)
    threads=[threading.Thread(target=drain,args=(stream,index),daemon=True) for index,stream in enumerate((process.stdout,process.stderr))]
    for thread in threads:thread.start()
    started=time.monotonic()
    try:
        while process.poll() is None:
            if overflow.is_set() or sum(Path(p).stat().st_size for p in watched if Path(p).exists())+sum(map(len,buffers))>max_bytes:
                raise ValueError('Tool output budget exceeded')
            if time.monotonic()-started>timeout:raise ValueError('Tool runtime budget exceeded')
            time.sleep(.02)
        for thread in threads:thread.join(timeout=1)
        if overflow.is_set() or any(thread.is_alive() for thread in threads):raise ValueError('Tool output budget exceeded')
        if sum(Path(p).stat().st_size for p in watched if Path(p).exists())+sum(map(len,buffers))>max_bytes:
            raise ValueError('Tool output budget exceeded')
        if process.returncode not in accepted_exit_codes:raise ValueError('Guarded tool failed; raw stderr omitted')
        return sanitize_output((buffers[0]+(b'\n'+buffers[1] if include_stderr else b'')).decode(errors='replace'))
    finally:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait()
        process.stdout.close();process.stderr.close()


def run_in_context(arguments,timeout,max_bytes,directory,watched=()):
    from .proxy import ProxyServer
    context=CONTEXT.get()
    if context is None:raise IsolationUnavailable('External execution requires an audited program/run context')
    workspace,program,tool,run_id=context
    if tool=='nmap':
        workspace.audit_egress(program,None,None,'denied','non-http-tool-cannot-use-proxy',tool,run_id,None,None,'process')
        raise IsolationUnavailable('Nmap cannot be confined through the HTTP proxy')
    if tool=='searchsploit':
        return run_guarded(arguments,timeout,max_bytes,directory,watched)
    with ProxyServer(workspace,program,tool,run_id,headers_supported=tool=='curl') as proxy:
        args=list(arguments)
        if tool=='curl':
            # Override legacy direct-connect flags. -q stays first; no proxy bypass is inherited.
            for flag in ('--resolve','--noproxy'):
                while flag in args:
                    index=args.index(flag);del args[index:index+2]
            args[2:2]=['--proxy',proxy.endpoint.url,'--proxy-user','expertool:'+proxy.endpoint.token,'--noproxy','']
            # proxy password flags would expose credentials through argv: use the proxy environment URL instead.
            index=args.index('--proxy-user');del args[index:index+2]
            index=args.index('--proxy');del args[index:index+2]
        try:
            return run_guarded(args,timeout,max_bytes,directory,watched,proxy.endpoint)
        except IsolationUnavailable:
            workspace.audit_egress(program,None,None,'denied','process-isolation-unavailable',tool,run_id,None,None,'process')
            raise
