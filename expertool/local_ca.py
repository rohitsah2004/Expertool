"""Explicit local CA lifecycle. Trust installation is always a manual user action."""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import uuid

from .scope import hostname

DEFAULT_CA=Path.home()/'.local'/'share'/'expertool'/'interception-ca'

class CAError(ValueError):pass


def openssl(arguments,secret_env=None):
    binary=shutil.which('openssl')
    if not binary:raise CAError('OpenSSL is required; install it manually')
    environment={'PATH':os.environ.get('PATH','/usr/bin:/bin')}
    if secret_env:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',secret_env) or len(os.environ.get(secret_env,''))<12:raise CAError('Set the requested CA passphrase environment variable (at least 12 characters)')
        environment[secret_env]=os.environ[secret_env]
    try:
        result=subprocess.run([binary,*arguments],stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=True,
                              env=environment)
        return result.stdout
    except (OSError,subprocess.SubprocessError):raise CAError('Local certificate operation failed; output omitted') from None


class LocalCA:
    def __init__(self,directory=DEFAULT_CA):self.directory=Path(directory).absolute();self.lock=threading.Lock()
    @classmethod
    def for_program(cls,root,program):
        if not isinstance(program,str) or not program.strip() or len(program)>200:raise CAError('Invalid CA program label')
        return cls(Path(root)/('program-'+hashlib.sha256(program.encode()).hexdigest()[:20]))
    def scope(self):
        path=self.directory/'scope.json'
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600:raise CAError('Legacy/unbound CA: explicitly create a constrained program CA')
        return json.loads(path.read_text())
    def enforce(self,program,policy):
        from .ca_scope import constraints
        metadata=self.scope()
        if metadata.get('program')!=program or metadata.get('constraints')!=constraints(policy):raise CAError('CA scope changed or program mismatch; explicitly rotate the CA')
        return self
    @property
    def key(self):return self.directory/'ca-key.pem'
    @property
    def cert(self):return self.directory/'ca-cert.pem'
    def validate(self):
        if self.directory.is_symlink() or not self.directory.is_dir() or stat.S_IMODE(self.directory.stat().st_mode)!=0o700:
            raise CAError('CA directory must be a real private directory (0700)')
        for path in (self.key,self.cert,self.directory/'ca.lock'):
            if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600:
                raise CAError('CA files must be regular private files (0600)')
        return self
    @contextmanager
    def lease(self,exclusive=False):
        self.validate()
        with (self.directory/'ca.lock').open('rb') as handle:
            try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB if exclusive else fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError:raise CAError('CA is in use; stop interception before changing it') from None
            try:yield self
            finally:fcntl.flock(handle,fcntl.LOCK_UN)
    def create(self,*,program,policy,passphrase_env=None):
        from .ca_scope import constraints,extension
        scoped=constraints(policy)
        if self.directory.exists() or self.directory.is_symlink():raise CAError('CA directory already exists; refusing replacement')
        self.directory.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.expertool-ca-',dir=self.directory.parent) as temporary:
            stage=Path(temporary)/'ca';stage.mkdir(mode=0o700)
            key=stage/'ca-key.pem';cert=stage/'ca-cert.pem'
            # Precreate sensitive output before OpenSSL opens it: never a transient 0644 key.
            for path in (key,cert,stage/'ca.lock',stage/'scope.json'):path.touch(mode=0o600,exist_ok=False)
            openssl(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(key)]+(['-aes-256-cbc','-pass','env:'+passphrase_env] if passphrase_env else []),secret_env=passphrase_env)
            openssl(['req','-new','-x509','-sha256','-days','365','-key',str(key),'-out',str(cert),
                '-subj','/CN=Expertool Program CA '+hashlib.sha256(program.encode()).hexdigest()[:12],'-addext','basicConstraints=critical,CA:TRUE',
                '-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash',
                '-addext','authorityKeyIdentifier=keyid:always','-addext','nameConstraints='+extension(scoped)]+(['-passin','env:'+passphrase_env] if passphrase_env else []),secret_env=passphrase_env)
            (stage/'scope.json').write_text(json.dumps({'program':program,'constraints':scoped,'passphrase_env':passphrase_env},sort_keys=True)+'\n')
            os.rename(stage,self.directory)
        self.validate()
        return {'public_sha256':hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).hexdigest(),'directory':str(self.directory),'trust_installed':False}
    def export_public(self,destination):
        with self.lease():
            data=self.cert.read_bytes()
            if b'PRIVATE KEY' in data:raise CAError('Refusing invalid public certificate')
            with Path(destination).open('xb') as target:target.write(data)
        return {'public_certificate':str(Path(destination).absolute())}
    def destroy(self):
        if set(path.name for path in self.directory.iterdir())!={'ca-key.pem','ca-cert.pem','ca.lock','scope.json'}:
            raise CAError('Unexpected CA-directory files; refusing partial destruction')
        with self.lease(exclusive=True):
            for name in ('ca-key.pem','ca-cert.pem','scope.json'):(self.directory/name).unlink()
            (self.directory/'ca.lock').unlink()
            self.directory.rmdir()
        return {'destroyed':True,'browser_trust_removed':False}
    def rotate(self,*,program,policy,passphrase_env=None):
        # Prepare the replacement before touching the current CA. Retain only
        # the old public certificate, never an archived signing key.
        temporary=self.directory.parent/('.rotation-'+uuid.uuid4().hex)
        replacement=LocalCA(temporary)
        replacement.create(program=program,policy=policy,passphrase_env=passphrase_env or self.scope().get('passphrase_env'))
        try:
            with self.lease(exclusive=True):
                old_public=self.cert.read_bytes()
                retired=self.directory.parent/('retired-public-'+hashlib.sha256(old_public).hexdigest()[:16]+'.pem')
                if not retired.exists():retired.write_bytes(old_public)
                old=self.directory.parent/('.retired-'+uuid.uuid4().hex)
                os.rename(self.directory,old)
                try:os.rename(temporary,self.directory)
                except BaseException:os.rename(old,self.directory);raise
                for name in ('ca-key.pem','ca-cert.pem','ca.lock','scope.json'):(old/name).unlink()
                old.rmdir()
            return {'rotated':True,'old_public_certificate':str(retired),'public_sha256':hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).hexdigest(),'warning':'Remove old CA trust manually; import the new public certificate manually.'}
        finally:
            if temporary.exists():replacement.destroy()
    def server_context(self,permit,guard):
        if not guard.unchanged(permit):raise CAError('Scope was revoked before certificate creation')
        from .ca_scope import permits_host
        metadata=self.scope()
        if not permits_host(metadata['constraints'],permit.host):raise CAError('Host outside certificate name constraints')
        host=hostname(permit.host)
        if host!=permit.host or host.endswith('.'):raise CAError('Noncanonical certificate host')
        with self.lock,self.lease(),tempfile.TemporaryDirectory(prefix='expertool-leaf-') as temporary:
            root=Path(temporary)
            for name in ('leaf-key.pem','leaf.pem'):(root/name).touch(mode=0o600)
            openssl(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(root/'leaf-key.pem')])
            try:ipaddress.IPv4Address(host);san='IP:'+host;subject='/'
            except ValueError:san='DNS:'+host;subject='/CN='+host
            openssl(['req','-new','-key',str(root/'leaf-key.pem'),'-out',str(root/'leaf.csr'),'-subj',subject])
            (root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nsubjectAltName=critical,'+san+'\n')
            openssl(['x509','-req','-in',str(root/'leaf.csr'),'-CA',str(self.cert),'-CAkey',str(self.key),
                '-set_serial','0x'+os.urandom(16).hex(),'-days','1','-sha256','-extfile',str(root/'extensions'),'-out',str(root/'leaf.pem')]+(['-passin','env:'+metadata['passphrase_env']] if metadata.get('passphrase_env') else []),secret_env=metadata.get('passphrase_env'))
            if not guard.unchanged(permit):raise CAError('Scope was revoked during certificate creation')
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['http/1.1']);context.load_cert_chain(root/'leaf.pem',root/'leaf-key.pem')
            def check_sni(sock,name,ctx):
                if name is not None and name.lower()!=host:return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            context.sni_callback=check_sni
            return context
