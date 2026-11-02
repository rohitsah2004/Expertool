import copy
import http.client
import os
import ssl
import sqlite3
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import test_intercept as fixtures
from expertool.egress import PolicySource
from expertool.intercept import ManualGuard
from expertool.send import RequestSpec,send_guarded,SendError

class SendTests(unittest.TestCase):
    setUpClass=classmethod(fixtures.InterceptionTests.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.InterceptionTests.tearDownClass.__func__)
    setUp=fixtures.InterceptionTests.setUp
    tearDown=fixtures.InterceptionTests.tearDown
    def send(self,method='GET',url=None,headers=(),body=b''):
        guard=ManualGuard(PolicySource(self.policy,self.w,'manual'),'intercept',self.run)
        return send_guarded(guard,guard.source,RequestSpec(method,url or f'http://127.0.0.1:{self.http.server_port}/',list(headers),body),source='browser')
    def test_scope_exclusion_methods_and_host_refusal(self):
        for method,url,headers in [('POST',None,()),('GET','http://outside.invalid/',()),('GET',None,[('Host','outside.invalid')])]:
            with self.subTest(method=method,url=url),self.assertRaises(SendError):self.send(method,url,headers)
        self.policy['exclude']=['127.0.0.1'];self.w.update_program('manual',self.policy)
        with self.assertRaises(SendError):self.send()
    def test_injection_source_timings_and_ordered_headers(self):
        headers=[('X-Test','one'),('User-Agent','browser')]
        result=self.send(headers=headers)
        self.assertEqual(headers,[('X-Test','one'),('User-Agent','browser')]);self.assertIn('user-agent',result.injected_headers)
        self.assertEqual(result.status,200);self.assertFalse(result.truncated);self.assertIn('total_seconds',result.timings)
        event=next(e for e in self.w.snapshot('manual')['egress'] if e['reason']=='manual-response-completed')
        self.assertEqual(event['source'],'browser');self.assertEqual(event['event_version'],3)
        self.assertTrue(self.w.verify_audit()['valid'])
    def test_certificate_errors_surface(self):
        with patch.dict(os.environ,{'SSL_CERT_FILE':''}):
            with self.assertRaises(ssl.SSLCertVerificationError):self.send(url=f'https://127.0.0.1:{self.https.server_port}/')
    def test_verified_tls(self):
        with patch.dict(os.environ,{'SSL_CERT_FILE':str(self.upstream_ca.cert)}):
            self.assertEqual(self.send(url=f'https://127.0.0.1:{self.https.server_port}/').status,200)
    def test_response_cap(self):
        self.policy['scan']['max_response_bytes']=1024;self.w.update_program('manual',self.policy)
        with patch('http.client.HTTPResponse.read',return_value=b'x'*1025):
            with self.assertRaises(SendError) as error:self.send()
        self.assertEqual(error.exception.reason,'response-budget-exceeded')
    def test_revocation_before_return(self):
        original=http.client.HTTPConnection.getresponse
        def revoke(connection):
            result=original(connection);policy=copy.deepcopy(self.policy);policy['interception']['enabled']=False;self.w.update_program('manual',policy);return result
        with patch('http.client.HTTPConnection.getresponse',revoke):
            with self.assertRaises(SendError):self.send()
    def test_version_two_schema_checkpoint_migrates_without_rehash(self):
        from expertool.audit import digest
        from expertool.workspace import Workspace
        self.w.audit_egress('manual','example.test',443,'denied','fixture','intercept',None,None,None,'intercept-tls',method='GET')
        row=dict(self.w.db.execute('SELECT * FROM egress_events').fetchone());row.pop('source');row['event_version']=2
        row['event_hash']=digest(row,row['prev_hash'])
        checkpoint={'last_id':row['id'],'event_hash':row['event_hash'],'count':1}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'v2.db';connection=sqlite3.connect(path)
            fields=','.join(key+(' INTEGER PRIMARY KEY' if key=='id' else ' INTEGER' if key in {'port','run_id','event_version'} else ' TEXT') for key in row)
            connection.execute('CREATE TABLE egress_events ('+fields+')')
            connection.execute('INSERT INTO egress_events VALUES('+','.join('?' for _ in row)+')',list(row.values()));connection.commit();connection.close()
            migrated=Workspace(path)
            try:
                self.assertTrue(migrated.verify_audit(checkpoint)['valid'])
                migrated.audit_egress('manual','example.test',443,'denied','fixture','intercept',None,None,None,'intercept-tls',method='GET',source='browser')
                self.assertTrue(migrated.verify_audit(checkpoint)['valid'])
            finally:migrated.close()

    def test_source_metadata_is_hash_protected(self):
        self.send();self.w.db.execute("UPDATE egress_events SET source='modified' WHERE source='browser'");self.w.db.commit()
        self.assertFalse(self.w.verify_audit()['valid'])
