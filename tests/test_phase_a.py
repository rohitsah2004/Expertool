import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from expertool.workspace import Workspace,markdown_report
from expertool.tool_identity import identify,probe,verify_identity,freshness
from expertool.scanner_profiles import scanner_settings
from expertool.scanners import run_scanner
from expertool.egress import EgressGuard,PolicySource,EgressDenied
from expertool.isolation import run_guarded
from expertool.proxy import ProxyServer,ProxyHandler

class ProvenanceTests(unittest.TestCase):
    def test_absolute_path_hash_missing_and_version_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'binary';file.write_bytes(b'fixture')
            result=identify('httpx',file)
            self.assertEqual(result['absolute_path'],str(file.resolve()))
            self.assertEqual(result['sha256'],hashlib.sha256(b'fixture').hexdigest())
            result.update(version='1.12.0',version_status='observed')
            self.assertTrue(verify_identity(result)['tested'])
            result['version']='9.9.9';self.assertFalse(verify_identity(result)['tested'])
            self.assertEqual(identify('httpx',None)['version_status'],'missing')
    def test_version_probe_redacts_and_retains_only_version_token(self):
        identity=identify('nuclei',sys.executable)
        with patch('expertool.isolation.run_guarded',return_value='Nuclei Engine Version: v3.11.1\nAuthorization: Bearer fixture-secret-value') as guarded:
            result=probe(identity)
        self.assertEqual(result['version'],'3.11.1');self.assertNotIn('fixture-secret-value',str(result))
        self.assertTrue(guarded.call_args.kwargs['include_stderr'])
        self.assertNotIn('endpoint',guarded.call_args.kwargs)
    def test_data_age_uses_oldest_file_and_reports_unknown_future(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'metadata.json').write_text('{}');(root/'dynamic_finders.yml').write_text('---')
            os.utime(root/'metadata.json',(1,1));os.utime(root/'dynamic_finders.yml',(86400,86400))
            age=freshness(root,30,True,clock=40*86400)
            self.assertTrue(age['stale']);self.assertGreater(age['age_days'],39)
            self.assertIn('threshold',age['warning'])
            self.assertIsNone(freshness(root/'missing')['date'])
            self.assertIn('future',freshness(root/'metadata.json',clock=0)['warning'])
    def test_policy_rejects_invalid_controls(self):
        for extra in [{'block_untested_versions':'yes'},{'stale_after_days':0},{'stale_after_days':True}]:
            with self.assertRaises(ValueError):scanner_settings({'scanners':extra})
    def test_untested_block_never_launches_scan_and_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'tool';path.write_text('fixture')
            w=Workspace(':memory:')
            try:
                policy=json.loads(Path('examples/scanner-lab-program.json').read_text());policy['scanners']['block_untested_versions']=True
                w.add_program('lab',policy)
                untested=identify('httpx',path);untested.update(version='9.9.9',version_string='fixture 9.9.9',version_status='observed')
                with patch('expertool.scanners.find_executable',return_value=str(path)),patch('expertool.tool_identity.probe',return_value=untested),patch('expertool.scanners.launch') as launch:
                    result=run_scanner(w,'lab','httpx','http://127.0.0.1:8901/')
                self.assertEqual(result['status'],'blocked');launch.assert_not_called()
                self.assertEqual(w.snapshot('lab')['runs'][0]['result']['tool_identity']['sha256'],untested['sha256'])
            finally:w.close()
    def test_report_discloses_date_age_and_version(self):
        w=Workspace(':memory:')
        try:
            w.add_program('lab',json.loads(Path('examples/scanner-lab-program.json').read_text()))
            run=w.start_run('lab','nuclei',{})
            w.finish_run(run,'completed',{'tool_identity':identify('nuclei',None),'data_freshness':freshness(None),'warnings':['Coverage unverified']})
            report=markdown_report(w.snapshot('lab'))
            self.assertIn('Fingerprint/database date: unavailable',report);self.assertIn('Coverage unverified',report)
        finally:w.close()

class AuditTests(unittest.TestCase):
    def append(self,w,reason='fixture'):
        w.audit_egress('lab','allowed.example',443,'denied',reason,'httpx',None,None,None,'http')
    def test_edit_middle_delete_and_tail_checkpoint(self):
        for mutation in ['edit','middle','tail']:
            w=Workspace(':memory:')
            try:
                for _ in range(3):self.append(w)
                initial=w.verify_audit();self.assertTrue(initial['valid'])
                if mutation=='edit':w.db.execute("UPDATE egress_events SET reason='changed' WHERE id=2")
                if mutation=='middle':w.db.execute('DELETE FROM egress_events WHERE id=2')
                if mutation=='tail':w.db.execute('DELETE FROM egress_events WHERE id=3')
                w.db.commit()
                self.assertFalse(w.verify_audit(initial['checkpoint'])['valid'])
            finally:w.close()
    def test_legacy_migration_and_no_silent_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'old.db';c=sqlite3.connect(path)
            c.execute('CREATE TABLE egress_events (id INTEGER PRIMARY KEY,program TEXT,host TEXT,port INTEGER,decision TEXT,reason TEXT,tool TEXT,run_id INTEGER,policy_version TEXT,resolved_ip TEXT,transport TEXT,created TEXT)')
            c.execute("INSERT INTO egress_events VALUES(1,'lab',NULL,NULL,'denied','old','http',NULL,NULL,NULL,'http','old-date')");c.commit();c.close()
            w=Workspace(path);self.assertEqual(w.verify_audit()['legacy_rows'],1)
            self.append(w);self.assertTrue(w.verify_audit()['valid'])
            w.db.execute('UPDATE egress_events SET event_hash=NULL WHERE id=2');w.db.commit();w.close()
            w=Workspace(path)
            try:self.assertFalse(w.verify_audit()['valid'])
            finally:w.close()
    def test_concurrent_append_is_one_chain_and_secret_redacted_before_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            w=Workspace(Path(directory)/'audit.db');errors=[]
            def worker():
                try:
                    for _ in range(8):self.append(w,'Authorization: Bearer never-store-this-value')
                except Exception as error:errors.append(type(error).__name__)
            threads=[threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:thread.start()
            for thread in threads:thread.join()
            try:
                self.assertEqual(errors,[]);self.assertEqual(w.verify_audit()['checked'],32)
                self.assertNotIn('never-store-this-value','\n'.join(w.db.iterdump()))
            finally:w.close()

class DNSHardeningTests(unittest.TestCase):
    def setUp(self):
        self.policy={'authorized':True,'include':['allowed.example'],'exclude':['8.8.4.0/24'],'allowed_modes':['active'],
                     'scan':{'ports':[443],'timeout':1}}
    def guard(self,answers):
        guard=EgressGuard(PolicySource(self.policy))
        with patch('expertool.egress.socket.getaddrinfo',return_value=answers):return guard.authorize('https://allowed.example/')
    def answers(self,*ips):return [(socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443)) for ip in ips]
    def test_all_a_aaaa_records_checked_and_only_ipv4_selected(self):
        permit=self.guard(self.answers('8.8.8.8','1.1.1.1','2606:4700:4700::1111'))
        self.assertEqual(permit.ips,['1.1.1.1','8.8.8.8'])
        for bad in ['8.8.4.4','10.0.0.1','::1','fc00::1','::ffff:8.8.8.8','fe80::1%en0','169.254.169.254']:
            with self.subTest(ip=bad),self.assertRaises(EgressDenied):self.guard(self.answers('8.8.8.8',bad))
    def test_ipv6_only_fails_closed(self):
        with self.assertRaises(EgressDenied):self.guard(self.answers('2606:4700:4700::1111'))
    def test_ip_notation_rejected_before_dns(self):
        policy=copy.deepcopy(self.policy);policy['include']=['* .invalid'.replace(' ','')]
        guard=EgressGuard(PolicySource(policy))
        for host in ['2130706433','0177.0.0.1','0x7f000001','127.1','127.0.0.1.','[::ffff:127.0.0.1]','[fe80::1%25en0]']:
            with self.subTest(host=host),patch('expertool.egress.socket.getaddrinfo') as dns:
                with self.assertRaises(EgressDenied):guard.authorize('http://'+host+'/')
                dns.assert_not_called()
    @unittest.skipUnless(platform.system()=='Darwin','macOS DNS/socket boundary')
    def test_child_dns_udp_tcp_and_connect_to_unvalidated_address_blocked(self):
        w=Workspace(':memory:');policy=json.loads(Path('examples/scanner-lab-program.json').read_text());w.add_program('lab',policy)
        script='''import socket,json
results=[]
for kind in ('udp','tcp'):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if kind=='udp' else socket.SOCK_STREAM);s.settimeout(.5)
  if kind=='udp':s.sendto(b'dns',('8.8.8.8',53))
  else:s.connect(('8.8.8.8',53))
  results.append('BYPASS')
 except OSError:results.append('blocked')
try:socket.getaddrinfo('unvalidated-dns-probe.invalid',443);results.append('BYPASS')
except OSError:results.append('blocked')
print(json.dumps(results))
'''
        try:
            with ProxyServer(w,'lab') as proxy,tempfile.TemporaryDirectory() as directory:
                result=run_guarded([sys.executable,'-c',script],3,4096,directory,endpoint=proxy.endpoint)
            self.assertEqual(json.loads(result),['blocked']*3)
        finally:w.close()

from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

class WireTarget(BaseHTTPRequestHandler):
    hits=[]
    def log_message(self,*args):pass
    def do_GET(self):
        type(self).hits.append((self.path,dict(self.headers)))
        if self.path=='/redirect':
            self.send_response(302);self.send_header('Location','http://169.254.169.254/latest/meta-data/');self.send_header('Content-Length','0');self.end_headers();return
        if self.path=='/stream':
            self.send_response(200);self.send_header('Content-Length','100000');self.end_headers()
            try:
                for _ in range(100):self.wfile.write(b'x'*100);self.wfile.flush();time.sleep(.03)
            except (OSError,ConnectionError):pass
            return
        self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')

class AdversarialProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),WireTarget)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.port=cls.server.server_port
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):
        self.w=Workspace(':memory:');WireTarget.hits=[]
        self.policy={'authorized':True,'include':['127.0.0.1'],'exclude':[],'allowed_modes':['active'],
          'scan':{'allow_private':True,'ports':[self.port],'timeout':1,'max_seconds':20,'rate_per_second':10},
          'egress':{'tunnel_seconds':3}}
        self.w.add_program('lab',self.policy)
    def tearDown(self):self.w.close()
    def wire(self,proxy,request):
        with socket.create_connection(('127.0.0.1',proxy.server_port),timeout=2) as sock:
            sock.sendall(request);chunks=[]
            while True:
                try:chunk=sock.recv(65536)
                except ConnectionResetError:break
                if not chunk:break
                chunks.append(chunk)
            return b''.join(chunks)
    def request(self,proxy,headers='',path='/'):
        return f'GET http://127.0.0.1:{self.port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nProxy-Authorization: {proxy.endpoint.authorization}\r\n{headers}\r\n'.encode()
    def test_keepalive_pipelined_authority_switch_never_reuses_permit(self):
        with ProxyServer(self.w,'lab') as proxy:
            first=self.request(proxy,'Connection: keep-alive\r\n')
            second=f'GET http://outside.invalid:{self.port}/ HTTP/1.1\r\nHost: outside.invalid:{self.port}\r\n\r\n'.encode()
            reply=self.wire(proxy,first+second)
        self.assertIn(b'200 OK',reply);self.assertEqual(len(WireTarget.hits),1)
    def test_host_mismatch_duplicate_host_and_proxy_auth_not_forwarded(self):
        with ProxyServer(self.w,'lab') as proxy:
            for headers in ['Host: outside.invalid\r\n','Host: 127.0.0.1:'+str(self.port)+'\r\n']:
                self.assertIn(b'403',self.wire(proxy,self.request(proxy,headers)))
            altered=self.request(proxy).replace(f'Host: 127.0.0.1:{self.port}'.encode(),b'Host: outside.invalid')
            self.assertIn(b'403',self.wire(proxy,altered));self.assertEqual(WireTarget.hits,[])
            self.assertIn(b'200 OK',self.wire(proxy,self.request(proxy)))
            self.assertNotIn('Proxy-Authorization',WireTarget.hits[0][1])
            self.assertNotIn(proxy.endpoint.token,str(WireTarget.hits))
    def test_conflicting_and_malformed_body_framing_is_rejected(self):
        headers=['Content-Length: 0\r\nContent-Length: 0\r\n','Content-Length: 0\r\nContent-Length: 1\r\n',
            'Content-Length: +0\r\n','Content-Length: -1\r\n','Content-Length: nope\r\n','Content-Length: 00\r\n',
            'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n','Transfer-Encoding:\r\n']
        with ProxyServer(self.w,'lab') as proxy:
            for value in headers:
                with self.subTest(headers=value):self.assertIn(b'400',self.wire(proxy,self.request(proxy,value)))
        self.assertEqual(WireTarget.hits,[])
    def test_header_and_total_size_limits(self):
        with ProxyServer(self.w,'lab') as proxy:
            for value in ['X-Large: '+'x'*9000+'\r\n',''.join('X-'+str(i)+': '+'x'*4000+'\r\n' for i in range(10))]:
                self.assertIn(b'431',self.wire(proxy,self.request(proxy,value)))
        self.assertEqual(WireTarget.hits,[])
    def test_slow_header_client_has_total_deadline(self):
        with patch.object(ProxyHandler,'header_timeout',.25),ProxyServer(self.w,'lab') as proxy:
            start=time.monotonic()
            with socket.create_connection(('127.0.0.1',proxy.server_port),timeout=1) as sock:
                sock.sendall(b'GET ');time.sleep(.15);sock.sendall(b'http://')
                time.sleep(.2)
                self.assertEqual(sock.recv(1),b'')
            self.assertLess(time.monotonic()-start,1)
        self.assertEqual(WireTarget.hits,[])
    def test_redirect_is_not_followed_and_metadata_admission_denied(self):
        with ProxyServer(self.w,'lab') as proxy:
            self.assertIn(b'302',self.wire(proxy,self.request(proxy,path='/redirect')))
            request=f'GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\nProxy-Authorization: {proxy.endpoint.authorization}\r\n\r\n'.encode()
            self.assertIn(b'403',self.wire(proxy,request))
        self.assertEqual([row[0] for row in WireTarget.hits],['/redirect'])
    def test_mid_transfer_connect_revocation_closes_active_stream(self):
        with ProxyServer(self.w,'lab') as proxy:
            with socket.create_connection(('127.0.0.1',proxy.server_port),timeout=1) as sock:
                authority=f'127.0.0.1:{self.port}'
                sock.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {proxy.endpoint.authorization}\r\n\r\n'.encode())
                head=b''
                while b'\r\n\r\n' not in head:head+=sock.recv(1)
                self.assertIn(b'200',head)
                sock.sendall(f'GET /stream HTTP/1.0\r\nHost: {authority}\r\n\r\n'.encode())
                self.assertIn(b'200',sock.recv(1024))
                changed=copy.deepcopy(self.policy);changed['automation']={'allowed':False}
                self.w.update_program('lab',changed)
                started=time.monotonic()
                while sock.recv(65536):
                    self.assertLess(time.monotonic()-started,1)
        self.assertTrue(any(r['reason']=='policy-revoked' for r in self.w.snapshot('lab')['egress']),self.w.snapshot('lab')['egress'])
        self.assertNotIn('Proxy-Authorization',WireTarget.hits[0][1])
