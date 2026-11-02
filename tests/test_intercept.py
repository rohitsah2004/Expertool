"""W1 acceptance uses two local CAs and owned HTTP/TLS fixtures only."""
import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from expertool.audit import GENESIS,digest
from expertool.egress import EgressDenied,PolicySource
from expertool.intercept import InterceptServer,ManualGuard
from expertool.local_ca import CAError,LocalCA
from expertool.manual_policy import interception_settings
from expertool.proxy import ProxyServer
from expertool.workspace import Workspace

class ManualTarget(BaseHTTPRequestHandler):
    hits=[]
    def log_message(self,*args):pass
    def do_GET(self):self.respond()
    def do_HEAD(self):self.respond()
    def do_OPTIONS(self):self.respond()
    def do_POST(self):self.respond()
    def do_PUT(self):self.respond()
    def do_PATCH(self):self.respond()
    def do_DELETE(self):self.respond()
    def respond(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        type(self).hits.append((self.command,self.path,dict(self.headers),body))
        response=json.dumps({'method':self.command,'user_agent':self.headers.get('User-Agent'),'researcher':self.headers.get('X-Researcher'),'body_size':len(body)}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(response)));self.send_header('Set-Cookie','fixture=never-store-response-cookie');self.end_headers()
        if self.command!='HEAD':self.wfile.write(response)

def policy_for(*ports):
    return {'authorized':True,'include':['127.0.0.1'],'exclude':[],'allowed_modes':['manual'],
        'automation':{'allowed':False},'interception':{'enabled':True},
        'scan':{'ports':list(ports),'allow_private':True,'timeout':2,'max_seconds':45,'max_requests':30,'rate_per_second':10,
                'user_agent':'Expertool-Manual-Fixture','request_headers':{'X-Researcher':'manual-fixture'}}}

@unittest.skipUnless(shutil.which('openssl'),'local certificate fixtures require existing OpenSSL')
class CATests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.ca=LocalCA(Path(self.temp.name)/'ca');self.ca.create()
    def tearDown(self):self.temp.cleanup()
    def test_destroy_refuses_unknown_files_before_deleting_key(self):
        (self.ca.directory/'public-copy.pem').write_text('public copy')
        with self.assertRaises(CAError):self.ca.destroy()
        self.assertTrue(self.ca.key.exists());self.assertTrue(self.ca.cert.exists())
    def test_key_permissions_public_only_export_and_no_replacement(self):
        self.assertEqual(stat.S_IMODE(self.ca.key.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(self.ca.directory.stat().st_mode),0o700)
        destination=Path(self.temp.name)/'public.pem';self.ca.export_public(destination)
        self.assertIn(b'BEGIN CERTIFICATE',destination.read_bytes());self.assertNotIn(b'PRIVATE KEY',destination.read_bytes())
        original=self.ca.key.read_bytes()
        with self.assertRaises(FileExistsError):self.ca.export_public(self.ca.key)
        with self.assertRaises(CAError):self.ca.create()
        self.assertEqual(self.ca.key.read_bytes(),original)
    def test_unsafe_permissions_symlinks_and_active_destroy_refused(self):
        self.ca.key.chmod(0o644)
        with self.assertRaises(CAError):self.ca.validate()
        self.ca.key.chmod(0o600)
        with self.ca.lease():
            with self.assertRaises(CAError):self.ca.destroy()
        self.ca.destroy();self.assertFalse(self.ca.directory.exists())
    def test_revoked_permit_never_signs(self):
        from types import SimpleNamespace
        with patch.object(ManualGuard,'unchanged',return_value=False):
            guard=ManualGuard(PolicySource(policy_for(443)),'intercept')
            with patch('expertool.local_ca.openssl') as sign:
                with self.assertRaises(CAError):self.ca.server_context(SimpleNamespace(host='outside.invalid'),guard)
                sign.assert_not_called()

@unittest.skipUnless(platform.system()=='Darwin' and shutil.which('openssl'),'macOS manual interception integration')
class InterceptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.ca=LocalCA(cls.root/'browser-ca');cls.ca.create()
        cls.upstream_ca=LocalCA(cls.root/'upstream-ca');cls.upstream_ca.create()
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),ManualTarget)
        cls.https=ThreadingHTTPServer(('127.0.0.1',0),ManualTarget)
        policy=policy_for(cls.https.server_port)
        guard=ManualGuard(PolicySource(policy),'intercept');permit=guard.authorize(f'https://127.0.0.1:{cls.https.server_port}/')
        ctx=cls.upstream_ca.server_context(permit,guard)
        cls.https.socket=ctx.wrap_socket(cls.https.socket,server_side=True)
        cls.threads=[threading.Thread(target=server.serve_forever,daemon=True) for server in (cls.http,cls.https)]
        for thread in cls.threads:thread.start()
    @classmethod
    def tearDownClass(cls):
        for server in (cls.http,cls.https):server.shutdown();server.server_close()
        for thread in cls.threads:thread.join()
        cls.temp.cleanup()
    def setUp(self):
        self.w=Workspace(':memory:');self.policy=policy_for(self.http.server_port,self.https.server_port)
        self.w.add_program('manual',self.policy);self.run=self.w.start_run('manual','intercept',{})
        ManualTarget.hits=[]
    def tearDown(self):self.w.close()
    def server(self):return InterceptServer(self.w,'manual',self.run,self.ca)
    def plain(self,server,method='GET',path='/',headers=None,body=None,host='127.0.0.1'):
        connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=4)
        try:
            connection.request(method,f'http://{host}:{self.http.server_port}'+path,body=body,
                headers={'Proxy-Authorization':server.authorization,**(headers or {})})
            response=connection.getresponse();return response.status,response.read()
        finally:connection.close()
    def tls(self,server,method='GET',path='/',headers=None,body=None,trust_upstream=True):
        browser=ssl.create_default_context(cafile=str(self.ca.cert))
        connection=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=browser,timeout=5)
        connection.set_tunnel('127.0.0.1',self.https.server_port,headers={'Proxy-Authorization':server.authorization})
        environment={'SSL_CERT_FILE':str(self.upstream_ca.cert)} if trust_upstream else {}
        with patch.dict(os.environ,environment,clear=False):
            try:
                connection.request(method,path,body=body,headers=headers or {})
                response=connection.getresponse();return response.status,response.read()
            finally:connection.close()
    def update(self):self.w.update_program('manual',self.policy)
    def test_manual_opt_in_is_required_and_unsupported_features_refused(self):
        for controls in [{},{'enabled':False},{'enabled':True,'passthrough':True},{'enabled':True,'websocket_capture':True},{'enabled':True,'raw_capture':True}]:
            policy=copy.deepcopy(self.policy);policy['interception']=controls
            with self.subTest(controls=controls),self.assertRaises(ValueError):interception_settings(policy)
    def test_loopback_separate_listener_and_authentication(self):
        with self.server() as server:
            self.assertEqual(server.server_address[0],'127.0.0.1')
            self.assertEqual(self.plain(server,headers={'Proxy-Authorization':'Basic invalid'})[0],407)
            self.assertEqual(self.plain(server)[0],200)
        self.assertEqual(len(ManualTarget.hits),1)
    def test_http_header_injection_audit_and_no_raw_storage(self):
        with self.server() as server:
            status,body=self.plain(server,path='/private-object?token=never-store-query',headers={'Authorization':'Bearer never-store-request-token','Cookie':'session=never-store-browser-cookie','User-Agent':'browser'})
            self.assertEqual(status,200);self.assertEqual(json.loads(body)['user_agent'],'Expertool-Manual-Fixture')
            self.assertEqual(json.loads(body)['researcher'],'manual-fixture')
            self.assertNotIn('Proxy-Authorization',ManualTarget.hits[0][2])
            token=server.token
        events=self.w.snapshot('manual')['egress'];event=next(e for e in events if e['reason']=='manual-request-forwarded')
        self.assertEqual(event['method'],'GET');self.assertEqual(event['path_hash'],hashlib.sha256(b'/private-object').hexdigest())
        self.assertEqual(json.loads(event['injected_headers']),['user-agent','x-researcher'])
        dump='\n'.join(self.w.db.iterdump())
        for secret in ['never-store-query','never-store-request-token','never-store-browser-cookie','never-store-response-cookie',token,'/private-object']:
            self.assertNotIn(secret,dump)
        self.assertTrue(self.w.verify_audit()['valid'])
    def test_tls_decryption_and_verified_upstream(self):
        with self.server() as server:
            status,body=self.tls(server,headers={'User-Agent':'browser'})
            self.assertEqual(status,200);self.assertEqual(json.loads(body)['researcher'],'manual-fixture')
        self.assertEqual(len(ManualTarget.hits),1)
        self.assertTrue(any(e['transport']=='intercept-tls' and e['method']=='GET' for e in self.w.snapshot('manual')['egress']))
    def test_untrusted_upstream_certificate_is_not_bypassed(self):
        with patch.dict(os.environ,{'SSL_CERT_FILE':''}),self.server() as server:
            status,body=self.tls(server,trust_upstream=False)
        self.assertEqual(status,502);self.assertIn(b'upstream-certificate-error',body);self.assertEqual(ManualTarget.hits,[])
        self.assertTrue(any(e['reason']=='upstream-certificate-error' for e in self.w.snapshot('manual')['egress']))
    def test_scope_and_exclusions_never_sign_outside_host(self):
        for excluded in [False,True]:
            self.policy['exclude']=['127.0.0.1'] if excluded else [];self.update()
            with self.server() as server,patch.object(self.ca,'server_context') as sign:
                connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
                target='127.0.0.1' if excluded else 'outside.invalid'
                authority=f'{target}:{self.https.server_port}'
                try:
                    connection.request('CONNECT',authority,headers={'Host':authority,'Proxy-Authorization':server.authorization})
                    response=connection.getresponse();self.assertEqual(response.status,403);response.read()
                finally:connection.close()
                sign.assert_not_called()
        self.assertEqual(ManualTarget.hits,[])
    def test_narrow_https_scope_is_checked_after_decryption(self):
        self.policy['asset_scope']={'include':[f'https://127.0.0.1:{self.https.server_port}/allowed/*'],'exclude':[]}
        self.policy['scan']['path_prefixes']=['/allowed'];self.update()
        with self.server() as server:
            self.assertEqual(self.tls(server,path='/allowed/item')[0],200)
            self.assertEqual(self.tls(server,path='/outside')[0],403)
        self.assertEqual([r[1] for r in ManualTarget.hits],['/allowed/item'])
    def test_methods_off_by_default_and_explicit_approval_required(self):
        with self.server() as server:
            for method in ('POST','PUT','PATCH','DELETE','TRACE'):
                self.assertEqual(self.plain(server,method=method,body=b'fixture')[0],405)
        self.assertEqual(ManualTarget.hits,[])
        self.policy['interception']['state_changing']={'enabled':True}
        with self.assertRaises(ValueError):interception_settings(self.policy)
        self.policy['interception']['state_changing'].update(approved_by='fixture-owner',approved_at='2026-11-01T12:00:00-06:00');self.update()
        with self.server() as server:
            for method in ('POST','PUT','PATCH','DELETE'):
                status,body=self.plain(server,method=method,body=b'fixture')
                self.assertEqual(status,200);self.assertEqual(json.loads(body)['body_size'],7)
    def test_automated_scanner_methods_remain_read_only(self):
        self.policy['allowed_modes'].append('active');self.policy['automation']={'allowed':True}
        self.policy['interception']['state_changing']={'enabled':True,'approved_by':'fixture-owner','approved_at':'2026-11-01T12:00:00Z'};self.update()
        with ProxyServer(self.w,'manual') as scanner:
            connection=http.client.HTTPConnection('127.0.0.1',scanner.server_port)
            connection.request('POST',f'http://127.0.0.1:{self.http.server_port}/',body=b'fixture',headers={'Proxy-Authorization':scanner.endpoint.authorization})
            response=connection.getresponse();self.assertEqual(response.status,405);response.read();connection.close()
        self.assertEqual(ManualTarget.hits,[])
    def test_websocket_and_host_switch_refused(self):
        with self.server() as server:
            self.assertEqual(self.plain(server,headers={'Upgrade':'websocket','Connection':'Upgrade'})[0],405)
            self.assertEqual(self.tls(server,headers={'Host':'outside.invalid'})[0],403)
            self.assertEqual(self.plain(server,headers={'Host':'outside.invalid'})[0],403)
        self.assertEqual(ManualTarget.hits,[])
    def test_policy_revocation_drops_idle_tls_and_blocks_later_requests(self):
        with self.server() as server:
            browser=ssl.create_default_context(cafile=str(self.ca.cert))
            client=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=browser,timeout=2)
            client.set_tunnel('127.0.0.1',self.https.server_port,headers={'Proxy-Authorization':server.authorization});client.connect()
            self.policy['interception']['enabled']=False;self.update()
            self.assertTrue(server.revoked.wait(2))
            try:self.assertEqual(client.sock.recv(1),b'')
            finally:client.close()
        self.assertEqual(ManualTarget.hits,[])
    def test_http2_preface_is_refused_without_forwarding(self):
        with self.server() as server:
            browser=ssl.create_default_context(cafile=str(self.ca.cert));browser.set_alpn_protocols(['h2'])
            client=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=browser,timeout=3)
            client.set_tunnel('127.0.0.1',self.https.server_port,headers={'Proxy-Authorization':server.authorization})
            try:
                client.connect();self.assertNotEqual(client.sock.selected_alpn_protocol(),'h2')
                client.sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                self.assertIn(b'505',client.sock.recv(4096))
            finally:client.close()
        self.assertEqual(ManualTarget.hits,[])
    def test_unsupported_platform_refuses_listener(self):
        with patch('expertool.intercept.platform.system',return_value='Linux'):
            with self.assertRaises(ValueError):self.server()
    def test_manual_framing_body_cap_and_read_only_body_refused(self):
        with self.server() as server:
            self.assertEqual(self.plain(server,body=b'body')[0],502)
            self.assertEqual(self.plain(server,headers={'Transfer-Encoding':'chunked'})[0],403)
        self.assertEqual(ManualTarget.hits,[])
    def test_cli_start_stop_ca_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);db=root/'cli.db';ca=root/'ca';public=root/'public.pem'
            base=[sys.executable,'-m','expertool','--db',str(db)]
            created=subprocess.run(base+['ca-create','--ca-dir',str(ca)],capture_output=True,text=True,check=True)
            self.assertFalse(json.loads(created.stdout)['trust_installed'])
            exported=subprocess.run(base+['ca-export-public','--ca-dir',str(ca),'--out',str(public)],capture_output=True,text=True,check=True)
            self.assertNotIn('PRIVATE KEY',public.read_text())
            w=Workspace(db);w.add_program('cli',self.policy);w.close()
            token='fixture-cli-interception-token-unique-2026'
            environment={**os.environ,'EXPERTOOL_INTERCEPT_TOKEN':token}
            process=subprocess.Popen(base+['intercept-start','--program','cli','--ca-dir',str(ca)],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                import select
                ready,_,_=select.select([process.stdout],[],[],5);self.assertTrue(ready,'CLI did not report its listener')
                line=process.stdout.readline();self.assertNotIn(token,line);started=json.loads(line)
                port=int(started['proxy'].rsplit(':',1)[1])
                stopped=subprocess.run(base+['intercept-stop','--port',str(port)],env=environment,capture_output=True,text=True,check=True,timeout=5)
                self.assertTrue(json.loads(stopped.stdout)['stopped'])
                stdout,stderr=process.communicate(timeout=5);self.assertEqual(process.returncode,0,stderr)
                self.assertNotIn(token,stdout+stderr)
            finally:
                if process.poll() is None:process.kill();process.communicate()
            w=Workspace(db)
            try:
                self.assertEqual(w.snapshot('cli')['runs'][0]['status'],'completed')
                self.assertNotIn(token,'\n'.join(w.db.iterdump()))
            finally:w.close()
            destroyed=subprocess.run(base+['ca-destroy','--ca-dir',str(ca)],capture_output=True,text=True,check=True)
            self.assertTrue(json.loads(destroyed.stdout)['destroyed']);self.assertFalse(ca.exists())
    def test_stopped_listener_invalidates_existing_permit(self):
        with self.server() as server:
            permit=server.guard.authorize(f'http://127.0.0.1:{self.http.server_port}/')
            self.assertTrue(server.unchanged(permit));server.stop();self.assertFalse(server.unchanged(permit))
    def test_ca_destroy_refused_while_listener_active(self):
        with self.server():
            with self.assertRaises(CAError):self.ca.destroy()
    def test_authenticated_stop_does_not_forward_target_request(self):
        with self.server() as server:
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
            connection.request('POST','/__expertool_stop',headers={'Proxy-Authorization':server.authorization,'Content-Length':'0'})
            response=connection.getresponse();self.assertEqual(response.status,200);response.read();connection.close()
            self.assertTrue(server.stopping.wait(1))
        self.assertEqual(ManualTarget.hits,[])

class AuditCompatibilityTests(unittest.TestCase):
    def test_policy_update_retries_short_shared_cache_read_lock(self):
        w=Workspace(':memory:');policy=policy_for(443);w.add_program('manual',policy)
        ready=threading.Event()
        def reader():
            with w.reader() as connection:
                connection.execute('BEGIN');connection.execute('SELECT * FROM programs').fetchall();ready.set();time.sleep(.05)
        thread=threading.Thread(target=reader);thread.start();self.assertTrue(ready.wait(1))
        try:
            policy['interception']['enabled']=False;w.update_program('manual',policy)
            self.assertFalse(w.policy('manual')['interception']['enabled'])
        finally:thread.join();w.close()

    def test_version_one_checkpoint_survives_metadata_schema_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'old.db';c=sqlite3.connect(path);c.row_factory=sqlite3.Row
            c.execute('CREATE TABLE egress_events (id INTEGER PRIMARY KEY,program TEXT,host TEXT,port INTEGER,decision TEXT,reason TEXT,tool TEXT,run_id INTEGER,policy_version TEXT,resolved_ip TEXT,transport TEXT,created TEXT,prev_hash TEXT,event_hash TEXT,chain_origin TEXT)')
            c.execute("INSERT INTO egress_events VALUES(1,'fixture','allowed.example',443,'denied','old','http',NULL,NULL,NULL,'http','old-date',?,NULL,'native')",(GENESIS,))
            row=dict(c.execute('SELECT * FROM egress_events').fetchone());value=digest(row,GENESIS)
            c.execute('UPDATE egress_events SET event_hash=?',(value,));c.commit();c.close()
            w=Workspace(path)
            try:
                checkpoint={'last_id':1,'event_hash':value,'count':1}
                self.assertTrue(w.verify_audit(checkpoint)['valid'])
                w.audit_egress('fixture','allowed.example',443,'allowed','manual-request-forwarded','intercept',None,None,'8.8.8.8','intercept-tls',method='GET',path_hash='a'*64,injected_headers=['user-agent'])
                self.assertTrue(w.verify_audit(checkpoint)['valid'])
                w.db.execute("UPDATE egress_events SET method='POST' WHERE id=2");w.db.commit()
                self.assertFalse(w.verify_audit()['valid'])
            finally:w.close()
