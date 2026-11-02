import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from expertool.execution import Client
from expertool.egress import EgressDenied
from expertool.isolation import IsolationUnavailable, run_guarded, verify_backend
from expertool.proxy import ProxyServer
from expertool.workspace import Workspace, markdown_report


class Target(BaseHTTPRequestHandler):
    hits=[]
    active=0
    peak=0
    lock=threading.Lock()

    def log_message(self,*args):pass

    def do_GET(self):
        with self.lock:
            Target.active+=1;Target.peak=max(Target.peak,Target.active)
        try:
            Target.hits.append((self.path,dict(self.headers)))
            if self.path=='/slow':time.sleep(.15)
            body=json.dumps({'ok':True,'user_agent':self.headers.get('User-Agent'),'researcher':self.headers.get('X-Researcher')}).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        finally:
            with self.lock:Target.active-=1


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target=ThreadingHTTPServer(('127.0.0.1',0),Target)
        cls.target_thread=threading.Thread(target=cls.target.serve_forever,daemon=True);cls.target_thread.start()
        cls.port=cls.target.server_port
        cls.url=f'http://127.0.0.1:{cls.port}'

    @classmethod
    def tearDownClass(cls):
        cls.target.shutdown();cls.target.server_close();cls.target_thread.join()

    def setUp(self):
        self.workspace=Workspace(':memory:')
        self.policy={'authorized':True,'include':['127.0.0.1','allowed.example'],'exclude':[],
            'allowed_modes':['active'],'automation':{'allowed':True,'tools':['http','curl','fixture']},
            'scan':{'allow_private':True,'ports':[self.port],'timeout':1,'rate_per_second':10,'max_requests':50,'max_seconds':20},
            'egress':{'global_concurrency':2,'target_concurrency':1,'tunnel_seconds':3}}
        self.workspace.add_program('lab',self.policy)
        self.run_id=self.workspace.start_run('lab','proxy-fixture',{})
        Target.hits=[];Target.peak=0

    def tearDown(self):self.workspace.close()

    def request(self,proxy,url,headers=None,method='GET'):
        connection=http.client.HTTPConnection(proxy.endpoint.host,proxy.endpoint.port,timeout=3)
        try:
            connection.request(method,url,headers={'Proxy-Authorization':proxy.endpoint.authorization,**(headers or {})})
            response=connection.getresponse();body=response.read()
            return response.status,body
        finally:connection.close()

    def tunnel(self,proxy):
        sock=socket.create_connection(('127.0.0.1',proxy.server_port),timeout=2)
        authority=f'127.0.0.1:{self.port}'
        sock.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {proxy.endpoint.authorization}\r\n\r\n'.encode())
        head=b''
        while b'\r\n\r\n' not in head:head+=sock.recv(1)
        return sock,head

    def test_in_scope_request_injects_headers_and_audits(self):
        self.policy['scan'].update({'user_agent':'Researcher/fixture','request_headers':{'X-Researcher':'fixture-id'}})
        self.workspace.update_program('lab',self.policy)
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            status,body=self.request(proxy,self.url+'/item')
        self.assertEqual(status,200)
        data=json.loads(body)
        self.assertEqual(data['user_agent'],'Researcher/fixture');self.assertEqual(data['researcher'],'fixture-id')
        row=self.workspace.snapshot('lab')['egress'][0]
        self.assertEqual((row['decision'],row['host'],row['port'],row['run_id']),('allowed','127.0.0.1',self.port,self.run_id))
        self.assertEqual(len(row['policy_version']),64)
        self.assertNotIn('Proxy-Authorization',str(Target.hits))

    def test_out_of_scope_and_excluded_hosts_never_contact_target(self):
        self.policy['exclude']=['allowed.example']
        self.workspace.update_program('lab',self.policy)
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            for url in [f'http://outside.example:{self.port}/',f'http://allowed.example:{self.port}/']:
                self.assertEqual(self.request(proxy,url)[0],403)
        self.assertEqual(Target.hits,[])
        self.assertTrue(all(row['decision']=='denied' for row in self.workspace.snapshot('lab')['egress']))

    def test_excluded_and_unapproved_resolved_addresses_blocked(self):
        self.policy['exclude']=['8.8.8.0/24']
        self.workspace.update_program('lab',self.policy)
        real=socket.getaddrinfo
        def dns(host,port,*args,**kwargs):
            if host=='allowed.example':return [(2,1,6,'',('8.8.8.8',port)),(2,1,6,'',('127.0.0.1',port))]
            return real(host,port,*args,**kwargs)
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy,patch('socket.getaddrinfo',side_effect=dns):
            self.assertEqual(self.request(proxy,f'http://allowed.example:{self.port}/')[0],403)
        self.assertEqual(Target.hits,[])
        self.policy['exclude']=[];self.policy['egress']['resolved_ip_ranges']=['9.9.9.0/24']
        self.workspace.update_program('lab',self.policy)
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            self.assertEqual(self.request(proxy,self.url+'/')[0],403)

    def test_dns_is_resolved_once_then_connection_is_pinned(self):
        real=socket.getaddrinfo;calls=[]
        def rebinding(host,port,*args,**kwargs):
            if host=='allowed.example':
                calls.append(host)
                return [(2,1,6,'',('127.0.0.1' if len(calls)==1 else '169.254.169.254',port))]
            return real(host,port,*args,**kwargs)
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy,patch('socket.getaddrinfo',side_effect=rebinding):
            self.assertEqual(self.request(proxy,f'http://allowed.example:{self.port}/')[0],200)
        self.assertEqual(len(calls),1)
        self.assertEqual(Target.hits[0][1]['Host'],f'allowed.example:{self.port}')

    def test_metadata_and_private_ranges_fail_closed(self):
        self.policy['include']=['allowed.example']
        self.workspace.update_program('lab',self.policy)
        real=socket.getaddrinfo
        for ip in ['127.0.0.1','169.254.169.254']:
            def dns(host,port,*args,**kwargs):
                if host=='allowed.example':return [(2,1,6,'',(ip,port))]
                return real(host,port,*args,**kwargs)
            with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy,patch('socket.getaddrinfo',side_effect=dns):
                self.assertEqual(self.request(proxy,f'http://allowed.example:{self.port}/')[0],403)
        self.assertEqual(Target.hits,[])

    def test_proxy_auth_framing_and_methods(self):
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            self.assertEqual(self.request(proxy,self.url+'/',{'Proxy-Authorization':'Basic invalid'})[0],407)
            self.assertEqual(self.request(proxy,self.url+'/',{'Host':'evil.example'})[0],403)
            self.assertEqual(self.request(proxy,self.url+'/',method='POST')[0],405)
        self.assertEqual(Target.hits,[])

    def test_connect_relay_full_origin_and_no_secret_logging(self):
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            sock,head=self.tunnel(proxy)
            try:
                self.assertIn(b'200 Connection established',head)
                sock.sendall(f'GET / HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n\r\n'.encode())
                self.assertIn(b'200 OK',sock.recv(4096))
            finally:sock.close()
            self.request(proxy,self.url+'/?token=fixture-sensitive-query')
            dump='\n'.join(self.workspace.db.iterdump())
            self.assertNotIn(proxy.endpoint.token,dump)
            self.assertNotIn('fixture-sensitive-query',dump)
        self.assertTrue(any(row['transport']=='connect' for row in self.workspace.snapshot('lab')['egress']))

    def test_connect_denies_path_constraints_and_uninjectable_headers(self):
        for change in [{'path_prefixes':['/allowed']},{'excluded_paths':['/private']},{'request_headers':{'X-Researcher':'required'}}]:
            self.policy['scan'].update(change);self.workspace.update_program('lab',self.policy)
            with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
                sock,head=self.tunnel(proxy);sock.close();self.assertIn(b'403',head)
            self.policy['scan'].pop(next(iter(change)))
        self.assertEqual(Target.hits,[])

    def test_live_policy_update_revokes_new_requests_and_active_tunnel(self):
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            self.assertEqual(self.request(proxy,self.url+'/')[0],200)
            sock,head=self.tunnel(proxy);self.assertIn(b'200',head)
            policy=copy.deepcopy(self.policy);policy['automation']['allowed']=False
            self.workspace.update_program('lab',policy)
            self.assertEqual(self.request(proxy,self.url+'/')[0],403)
            try:
                sock.settimeout(1);self.assertEqual(sock.recv(1),b'')
            finally:sock.close()
        self.assertTrue(any(row['reason']=='policy-revoked' for row in self.workspace.snapshot('lab')['egress']))

    def test_direct_worker_reloads_policy_between_requests(self):
        client=Client(self.policy,workspace=self.workspace,program='lab',run_id=self.run_id)
        self.assertEqual(client.get(self.url+'/').status,200)
        policy=copy.deepcopy(self.policy);policy['exclude']=['127.0.0.1'];policy['include']=['allowed.example']
        self.workspace.update_program('lab',policy)
        with self.assertRaises(EgressDenied):client.get(self.url+'/')
        self.assertEqual(len(Target.hits),1)

    def test_worker_can_route_through_proxy(self):
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            client=Client(self.policy,workspace=self.workspace,program='lab',run_id=self.run_id,proxy=proxy.endpoint)
            self.assertEqual(client.get(self.url+'/').status,200)
        self.assertEqual(len(Target.hits),1)

    def test_two_proxies_share_concurrency_and_run_request_budget(self):
        self.policy['egress']['global_concurrency']=1
        self.policy['egress']['target_concurrency']=2
        self.workspace.update_program('lab',self.policy)
        responses=[]
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as first,ProxyServer(self.workspace,'lab',run_id=self.run_id) as second:
            threads=[threading.Thread(target=lambda p=p:responses.append(self.request(p,self.url+'/slow')[0])) for p in (first,second)]
            for thread in threads:thread.start()
            for thread in threads:thread.join()
        self.assertEqual(responses,[200,200]);self.assertEqual(Target.peak,1)

    def test_proxy_enforces_shared_request_count(self):
        self.policy['scan']['max_requests']=1
        self.workspace.update_program('lab',self.policy)
        with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy:
            self.assertEqual(self.request(proxy,self.url+'/')[0],200)
            self.assertNotEqual(self.request(proxy,self.url+'/')[0],200)
        self.assertEqual(len(Target.hits),1)

    @unittest.skipUnless(shutil.which('openssl'),'OpenSSL local TLS fixture')
    def test_real_verified_https_through_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cert=root/'cert.pem';key=root/'key.pem';cfg=root/'cert.cnf'
            cfg.write_text('[req]\ndistinguished_name=dn\nx509_extensions=san\nprompt=no\n[dn]\nCN=127.0.0.1\n[san]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(cfg),'-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            server=ThreadingHTTPServer(('127.0.0.1',0),Target)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            self.policy['scan']['ports'].append(server.server_port)
            self.workspace.update_program('lab',self.policy)
            try:
                with ProxyServer(self.workspace,'lab',run_id=self.run_id) as proxy,patch.dict(os.environ,{'SSL_CERT_FILE':str(cert)}):
                    client=Client(self.policy,workspace=self.workspace,program='lab',run_id=self.run_id,proxy=proxy.endpoint)
                    self.assertEqual(client.get(f'https://127.0.0.1:{server.server_port}/').status,200)
            finally:server.shutdown();server.server_close();thread.join()

    def test_new_evidence_and_reports_are_redacted(self):
        token='ghp_'+'A'*32
        self.workspace.import_records('lab',[{'url':self.url+'/?token=unsafe-query','findings':[{
            'check_id':'fixture','title':'fixture secret','severity':'info','evidence':'Authorization: Bearer private-test-value\nAPI key: '+token}],
            'metadata':{'Authorization':'Bearer never-store-this','token':token}}],'fixture')
        dump='\n'.join(self.workspace.db.iterdump())
        report=markdown_report(self.workspace.snapshot('lab'))
        for secret in [token,'private-test-value','never-store-this','unsafe-query']:
            self.assertNotIn(secret,dump);self.assertNotIn(secret,report)

    def test_no_isolation_backend_refuses_launch_before_child(self):
        with patch('expertool.isolation.platform.system',return_value='Linux'),patch('expertool.isolation.subprocess.Popen') as process:
            with self.assertRaises(IsolationUnavailable):run_guarded([sys.executable,'-c','pass'],1,1024,'/tmp')
            process.assert_not_called()

    def test_global_limit_cannot_be_widened_by_another_program(self):
        from expertool.budgets import SharedLimits
        limits=SharedLimits();entered=threading.Event();ready=threading.Event()
        config={'timeout':1,'rate_per_second':10,'max_requests':10}
        def second():
            ready.set()
            with limits.acquire('second','other.example',config,{'global_concurrency':4,'target_concurrency':4}):entered.set()
        with limits.acquire('first','first.example',config,{'global_concurrency':1,'target_concurrency':1}):
            thread=threading.Thread(target=second);thread.start();self.assertTrue(ready.wait(1))
            self.assertFalse(entered.wait(.05))
        thread.join(timeout=2);self.assertTrue(entered.is_set())

    @unittest.skipUnless(platform.system()=='Darwin' and shutil.which('sandbox-exec'),'macOS isolation integration')
    def test_real_process_ignoring_proxy_is_blocked(self):
        with ProxyServer(self.workspace,'lab','fixture',self.run_id) as proxy,tempfile.TemporaryDirectory() as directory:
            self.assertEqual(verify_backend(proxy.endpoint),'macos-seatbelt-verified')
            script="import socket\ntry:\n socket.create_connection(('127.0.0.1',PORT),timeout=1);print('BYPASS')\nexcept OSError:print('BLOCKED')".replace('PORT',str(self.port))
            output=run_guarded([sys.executable,'-c',script],2,4096,directory,endpoint=proxy.endpoint)
            self.assertEqual(output.strip(),'BLOCKED')
        self.assertEqual(Target.hits,[])

    @unittest.skipUnless(platform.system()=='Darwin' and shutil.which('curl'),'guarded curl integration')
    def test_real_guarded_curl_can_use_proxy(self):
        from expertool.isolation import guard_context,run_in_context
        with tempfile.TemporaryDirectory() as directory,guard_context(self.workspace,'lab','curl',self.run_id):
            output=run_in_context(['curl','-q','--silent','--show-error','--max-time','2',self.url+'/'],3,16384,directory)
        self.assertTrue(json.loads(output)['ok'])
        self.assertEqual(len(Target.hits),1)


if __name__=='__main__':unittest.main()
