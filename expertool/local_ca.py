"""Explicit local CA lifecycle. Trust installation is always a manual user action."""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading

from .scope import hostname

DEFAULT_CA=Path.home()/'.local'/'share'/'expertool'/'interception-ca'

class CAError(ValueError):pass


def openssl(arguments):
    binary=shutil.which('openssl')
    if not binary:raise CAError('OpenSSL is required; install it manually')
    try:
        result=subprocess.run([binary,*arguments],stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=True,
                              env={'PATH':os.environ.get('PATH','/usr/bin:/bin')})
        return result.stdout
    except (OSError,subprocess.SubprocessError):raise CAError('Local certificate operation failed; output omitted') from None


class LocalCA:
    def __init__(self,directory=DEFAULT_CA):self.directory=Path(directory).absolute();self.lock=threading.Lock()
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
    def create(self):
        if self.directory.exists() or self.directory.is_symlink():raise CAError('CA directory already exists; refusing replacement')
        self.directory.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.expertool-ca-',dir=self.directory.parent) as temporary:
            stage=Path(temporary)/'ca';stage.mkdir(mode=0o700)
            key=stage/'ca-key.pem';cert=stage/'ca-cert.pem'
            # Precreate sensitive output before OpenSSL opens it: never a transient 0644 key.
            for path in (key,cert,stage/'ca.lock'):path.touch(mode=0o600,exist_ok=False)
            openssl(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(key)])
            openssl(['req','-new','-x509','-sha256','-days','365','-key',str(key),'-out',str(cert),
                '-subj','/CN=Expertool Local Interception CA','-addext','basicConstraints=critical,CA:TRUE',
                '-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash',
                '-addext','authorityKeyIdentifier=keyid:always'])
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
        if set(path.name for path in self.directory.iterdir())!={'ca-key.pem','ca-cert.pem','ca.lock'}:
            raise CAError('Unexpected CA-directory files; refusing partial destruction')
        with self.lease(exclusive=True):
            for name in ('ca-key.pem','ca-cert.pem'):(self.directory/name).unlink()
            (self.directory/'ca.lock').unlink()
            self.directory.rmdir()
        return {'destroyed':True,'browser_trust_removed':False}
    def server_context(self,permit,guard):
        if not guard.unchanged(permit):raise CAError('Scope was revoked before certificate creation')
        host=hostname(permit.host)
        if host!=permit.host or host.endswith('.'):raise CAError('Noncanonical certificate host')
        with self.lock,self.lease(),tempfile.TemporaryDirectory(prefix='expertool-leaf-') as temporary:
            root=Path(temporary)
            for name in ('leaf-key.pem','leaf.pem'):(root/name).touch(mode=0o600)
            openssl(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(root/'leaf-key.pem')])
            openssl(['req','-new','-key',str(root/'leaf-key.pem'),'-out',str(root/'leaf.csr'),'-subj','/CN='+host])
            try:ipaddress.IPv4Address(host);san='IP:'+host
            except ValueError:san='DNS:'+host
            (root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nsubjectAltName='+san+'\n')
            openssl(['x509','-req','-in',str(root/'leaf.csr'),'-CA',str(self.cert),'-CAkey',str(self.key),
                '-set_serial','0x'+os.urandom(16).hex(),'-days','1','-sha256','-extfile',str(root/'extensions'),'-out',str(root/'leaf.pem')])
            if not guard.unchanged(permit):raise CAError('Scope was revoked during certificate creation')
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['http/1.1']);context.load_cert_chain(root/'leaf.pem',root/'leaf-key.pem')
            def check_sni(sock,name,ctx):
                if name is not None and name.lower()!=host:return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            context.sni_callback=check_sni
            return context
