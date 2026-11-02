import copy
import socket
import unittest
from unittest.mock import patch
import test_intercept as fixtures
from expertool.manual_policy import interception_settings
from expertool.passthrough import controls,authorize
from expertool.egress import EgressDenied

class PassthroughTests(unittest.TestCase):
    setUpClass=classmethod(fixtures.InterceptionTests.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.InterceptionTests.tearDownClass.__func__)
    setUp=fixtures.InterceptionTests.setUp
    tearDown=fixtures.InterceptionTests.tearDown
    server=fixtures.InterceptionTests.server
    def enable(self):
        self.policy['interception']['passthrough']={'enabled':True,'hosts':['cdn.example.test'],'ports':[self.http.server_port],
          'approved_by':'fixture','approved_at':'2026-11-01T12:00:00Z'}
        self.w.update_program('manual',self.policy)
    def route(self,ips=('8.8.8.8',)):
        original=socket.getaddrinfo
        def dns(host,port,*args,**kwargs):
            if host=='cdn.example.test':return [(socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,port)) for ip in ips]
            return original(host,port,*args,**kwargs)
        return patch('socket.getaddrinfo',side_effect=dns)
    def connect(self,server,host='cdn.example.test'):
        sock=socket.create_connection(('127.0.0.1',server.server_port),timeout=3)
        authority=f'{host}:{self.http.server_port}'
        sock.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {server.authorization}\r\n\r\n'.encode())
        head=b''
        while b'\r\n\r\n' not in head:
            data=sock.recv(1)
            if not data:break
            head+=data
        return sock,head
    def dial(self):
        original=socket.create_connection
        def connect(address,*args,**kwargs):return original(('127.0.0.1',self.http.server_port) if address[0]=='8.8.8.8' else address,*args,**kwargs)
        return patch('socket.create_connection',side_effect=connect)
    def test_blind_relay_no_ca_no_header_injection_and_audit(self):
        self.enable()
        with self.server() as server,self.route(),self.dial(),patch.object(self.ca,'server_context') as ca:
            sock,head=self.connect(server)
            try:
                self.assertIn(b'200',head);sock.sendall(b'GET / HTTP/1.0\r\nHost: cdn.example.test\r\nUser-Agent: unmodified-browser\r\n\r\n')
                self.assertIn(b'200',sock.recv(4096))
            finally:sock.close()
            ca.assert_not_called()
        hit=fixtures.ManualTarget.hits[0]
        self.assertEqual(hit[2]['User-Agent'],'unmodified-browser');self.assertNotIn('X-Researcher',hit[2]);self.assertNotIn('Proxy-Authorization',hit[2])
        event=next(e for e in self.w.snapshot('manual')['egress'] if e['reason']=='passthrough')
        self.assertEqual(event['transport'],'passthrough');self.assertEqual(event['injected_headers'],'[]')
    def test_relay_error_never_injects_http_into_acknowledged_tunnel(self):
        self.enable()
        with self.server() as server,self.route(),self.dial(),patch('expertool.intercept.select.select',side_effect=OSError('fixture')):
            sock,head=self.connect(server)
            try:self.assertIn(b'200',head);self.assertEqual(sock.recv(4096),b'')
            finally:sock.close()

    def test_unlisted_and_excluded_hosts_refused(self):
        self.enable()
        with self.server() as server:
            sock,head=self.connect(server,'unlisted.invalid');sock.close();self.assertIn(b'403',head)
        self.policy['exclude']=['cdn.example.test']
        with self.assertRaises(ValueError):interception_settings(self.policy)
    def test_private_mapped_excluded_and_mixed_answers_fail_closed(self):
        self.enable()
        for ips in [('127.0.0.1',),('8.8.8.8','10.0.0.1'),('8.8.8.8','::ffff:8.8.8.8'),('8.8.8.8','169.254.169.254')]:
            with self.subTest(ips=ips),self.server() as server,self.route(ips):
                with self.assertRaises(EgressDenied):authorize(server.guard,'cdn.example.test',self.http.server_port)
    def test_revocation_and_tunnel_caps(self):
        for change in ['revoke','bytes','time']:
            self.enable();self.policy['egress']={'tunnel_seconds':1,'tunnel_bytes':1024};self.w.update_program('manual',self.policy)
            with self.subTest(change=change),self.server() as server,self.route(),self.dial():
                sock,head=self.connect(server);self.assertIn(b'200',head)
                try:
                    if change=='revoke':
                        policy=copy.deepcopy(self.policy);policy['interception']['passthrough']=False;self.w.update_program('manual',policy)
                    elif change=='bytes':sock.sendall(b'x'*1025)
                    self.assertEqual(sock.recv(1),b'')
                finally:sock.close()
    def test_wildcard_public_suffix_and_approval_validation(self):
        self.enable()
        for host in ['*','*.com','*.co.uk','*.github.io','*.unreviewed.example']:
            self.policy['interception']['passthrough']['hosts']=[host]
            with self.subTest(host=host),self.assertRaises(ValueError):controls(self.policy)
        self.policy['interception']['passthrough']['hosts']=['*.gstatic.com'];self.assertTrue(controls(self.policy)['warnings'])
        self.policy['interception']['passthrough'].pop('approved_by')
        with self.assertRaises(ValueError):controls(self.policy)
