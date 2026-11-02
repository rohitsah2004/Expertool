import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from expertool.execution import Client, checked_url, load_auth, load_checks, scan, validate_finding, access_check
from expertool.jobs import add_schedule, run_due, set_schedule, discover
from expertool.workspace import Workspace


class Fixture(BaseHTTPRequestHandler):
    paths = []
    last_headers = {}
    secure_headers = False
    expose_canary = True

    def log_message(self, *args):
        pass

    def do_GET(self):
        Fixture.paths.append(self.path)
        Fixture.last_headers = dict(self.headers)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.2:9/blocked')
            self.end_headers()
            return
        authenticated = self.headers.get('Authorization') == 'Bearer fixture-secret'
        other = self.headers.get('Authorization') == 'Bearer other-fixture'
        denied = self.path == '/owned' and not authenticated and not (other and Fixture.expose_canary)
        self.send_response(403 if denied else (401 if self.path == '/protected' and not authenticated else 200))
        self.send_header('Content-Type', 'text/html')
        if Fixture.secure_headers:
            self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Set-Cookie', 'fixture=secret-cookie; Path=/')
        self.end_headers()
        if self.path == '/':
            body = '<title>Fixture</title><a href="/next">Next</a><a href="/excluded">Excluded</a><a href="/logout">Logout</a><a href="/redirect">Redirect</a><form method="post" action="/never">'
        elif self.path == '/marker':
            body = 'EXPERTOOL_FIXTURE_MARKER'
        elif self.path == '/big':
            body = 'x' * 3000
        elif self.path == '/owned':
            body = 'EXPERTOOL_CANARY_FIXTURE' if not denied else 'Forbidden'
        else:
            body = '<title>Bearer fixture-secret</title>' if authenticated else 'Fixture response'
        self.wfile.write(body.encode())


class ExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        self.workspace = Workspace(':memory:')
        self.policy = {'authorized': True, 'include': ['127.0.0.1'], 'exclude': [], 'allowed_modes': ['passive', 'active'],
            'scan': {'allow_private': True, 'ports': [self.server.server_port], 'rate_per_second': 10, 'max_requests': 20,
                     'max_seconds': 15, 'timeout': 1, 'excluded_paths': ['/excluded']}}
        self.workspace.add_program('fixture', self.policy)
        Fixture.paths = []
        Fixture.secure_headers = False
        Fixture.expose_canary = True

    def tearDown(self):
        self.workspace.close()

    def test_crawl_respects_scope_and_never_submits_forms(self):
        result = scan(self.workspace, 'fixture', [self.origin + '/'])
        self.assertEqual(result['status'], 'completed')
        self.assertIn('/next', Fixture.paths)
        self.assertNotIn('/excluded', Fixture.paths)
        self.assertNotIn('/logout', Fixture.paths)
        self.assertNotIn('/never', Fixture.paths)
        self.assertTrue(any(event['event'] == 'navigation-blocked' for event in result['events']))
        snapshot = self.workspace.snapshot('fixture')
        self.assertEqual(snapshot['runs'][0]['status'], 'completed')
        self.assertNotIn('secret-cookie', str(snapshot))

    def test_auth_comparison_and_credential_redaction(self):
        auth = {'name': 'fixture-account', 'origin': self.origin, 'headers': {'Authorization': 'Bearer fixture-secret'}}
        scan(self.workspace, 'fixture', [self.origin+'/protected'], auth=auth, crawl=False, compare_auth=True)
        snapshot = self.workspace.snapshot('fixture')
        comparison = snapshot['observations'][0]['metadata']['auth_comparison']
        self.assertEqual((comparison['authenticated_status'], comparison['anonymous_status']), (200, 401))
        self.assertNotIn('fixture-secret', str(snapshot))
        self.assertEqual(snapshot['findings'][0]['state'], 'candidate')

    def test_custom_checks_and_revalidation_do_not_confirm_impact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'checks.json'
            path.write_text(json.dumps([{'id': 'fixture-marker', 'name': 'Fixture marker', 'path': '/marker', 'severity': 'info', 'match': {'status':200, 'body_contains':'EXPERTOOL_FIXTURE_MARKER'}}]))
            checks = load_checks(path)
        scan(self.workspace, 'fixture', [self.origin+'/next'], checks=checks, crawl=False)
        finding = next(f for f in self.workspace.snapshot('fixture')['findings'] if f['check_id']=='custom.fixture-marker')
        result = validate_finding(self.workspace, finding['id'], checks=checks)
        self.assertEqual(result['verdict'], 'reproduced')
        snapshot = self.workspace.snapshot('fixture')
        self.assertEqual(next(f for f in snapshot['findings'] if f['id']==finding['id'])['state'], 'candidate')
        self.assertEqual(len(snapshot['validations']), 1)

    def test_fixed_condition_reports_not_reproduced(self):
        scan(self.workspace, 'fixture', [self.origin+'/next'], crawl=False)
        finding = next(f for f in self.workspace.snapshot('fixture')['findings'] if f['check_id']=='headers.x-content-type-options')
        Fixture.secure_headers = True
        self.assertEqual(validate_finding(self.workspace, finding['id'])['verdict'], 'not-reproduced')

    def test_private_ip_and_rebinding_answer_blocked_before_connect(self):
        public = dict(self.policy, scan={**self.policy['scan'], 'allow_private': False})
        with patch('expertool.execution.socket.create_connection') as connection:
            with self.assertRaisesRegex(ValueError, 'Non-public'):
                Client(public).get(self.origin)
            connection.assert_not_called()
        mixed = [(2, 1, 6, '', ('8.8.8.8',80)), (2, 1, 6, '', ('127.0.0.1',80))]
        with patch('expertool.execution.socket.getaddrinfo', return_value=mixed), patch('expertool.execution.socket.create_connection') as connection:
            with self.assertRaises(ValueError):
                Client(public).get(self.origin)
            connection.assert_not_called()

    def test_active_permission_ports_and_paths(self):
        denied = dict(self.policy, allowed_modes=['passive'])
        with self.assertRaises(ValueError):
            Client(denied)
        for target in [self.origin+'/excluded/child', self.origin+'/%252e%252e/excluded', 'http://127.0.0.1:1/', self.origin+'/logout', 'http://127.0.0.2/']:
            with self.assertRaises(ValueError):
                checked_url(self.policy, target)

    def test_request_and_body_budgets(self):
        self.policy['scan'].update({'max_requests': 1, 'max_response_bytes': 1024})
        client = Client(self.policy)
        response = client.get(self.origin+'/big')
        self.assertEqual(len(response.body), 1024)
        self.assertTrue(response.truncated)
        with self.assertRaisesRegex(ValueError, 'budget'):
            client.get(self.origin+'/next')

    def test_auth_env_profile_and_origin_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'auth.json'
            path.write_text(json.dumps({'name':'test', 'origin':self.origin, 'headers_env':{'Authorization':'EXPERTOOL_TEST_TOKEN'}}))
            with patch.dict(os.environ, {'EXPERTOOL_TEST_TOKEN':'Bearer fixture-secret'}):
                auth = load_auth(path)
            auth['origin'] = 'https://other.example.com'
            with self.assertRaisesRegex(ValueError, 'origin mismatch'):
                Client(self.policy, auth).get(self.origin)

    def test_due_schedule_disable_and_repeat_guard(self):
        schedule = add_schedule(self.workspace, 'fixture', [self.origin+'/next'], 60)
        self.assertEqual(run_due(self.workspace)['status'], 'completed')
        self.assertIsNone(run_due(self.workspace))
        self.workspace.db.execute('UPDATE schedules SET next_due=0')
        self.workspace.db.commit()
        set_schedule(self.workspace, schedule['schedule_id'], False)
        self.assertIsNone(run_due(self.workspace))

    def test_missing_tool_and_out_of_scope_discovery(self):
        with patch('expertool.jobs.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'not installed'):
                discover(self.workspace, 'fixture', '127.0.0.1')
        with self.assertRaisesRegex(ValueError, 'outside'):
            discover(self.workspace, 'fixture', 'outside.example')

    def test_controlled_canary_boundary_and_remediation_recheck(self):
        owner = {'name':'owner', 'origin':self.origin, 'headers':{'Authorization':'Bearer fixture-secret'}}
        other = {'name':'other', 'origin':self.origin, 'headers':{'Authorization':'Bearer other-fixture'}}
        result = access_check(self.workspace,'fixture',self.origin+'/owned',owner,other,'EXPERTOOL_CANARY_FIXTURE')
        self.assertEqual(result['verdict'], 'reproduced')
        self.assertIsNotNone(result['finding_id'])
        Fixture.expose_canary = False
        fixed = access_check(self.workspace,'fixture',self.origin+'/owned',owner,other,'EXPERTOOL_CANARY_FIXTURE')
        self.assertEqual(fixed['verdict'], 'not-reproduced')
        self.assertEqual(fixed['finding_id'],result['finding_id'])
        snapshot = self.workspace.snapshot('fixture')
        self.assertEqual(snapshot['findings'][0]['state'],'candidate')
        self.assertEqual(len(snapshot['validations']),2)
        self.assertNotIn('EXPERTOOL_CANARY_FIXTURE',str(snapshot))

    def test_subfinder_process_adapter_with_local_fixture_executable(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory)/'subfinder-fixture'
            executable.write_text('#!'+str(Path(sys.executable).resolve())+'\nimport json\nprint(json.dumps({"host":"127.0.0.1","source":"fixture"}))\n')
            executable.chmod(0o700)
            with patch('expertool.jobs.shutil.which', return_value=str(executable)):
                result = discover(self.workspace,'fixture','127.0.0.1',timeout=2)
            self.assertEqual(result['assets_added'],1)
            self.assertEqual(self.workspace.snapshot('fixture')['runs'][0]['status'],'completed')

    def test_scheduler_failure_releases_lease(self):
        add_schedule(self.workspace,'fixture',[self.origin+'/next'],60)
        with patch('expertool.jobs.scan',side_effect=ValueError('fixture failure')):
            self.assertEqual(run_due(self.workspace)['status'],'failed')
        row = self.workspace.db.execute('SELECT * FROM schedules').fetchone()
        self.assertEqual(row['lease_until'],0)
        self.assertEqual(row['last_status'],'failed')

    def test_subfinder_timeout_marks_failed_and_stops_process(self):
        import sys
        import time
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'slow-subfinder-fixture'
            executable.write_text('#!'+str(Path(sys.executable).resolve())+'\nimport time\ntime.sleep(10)\n')
            executable.chmod(0o700)
            start=time.monotonic()
            with patch('expertool.jobs.shutil.which',return_value=str(executable)):
                with self.assertRaisesRegex(ValueError,'budget'):
                    discover(self.workspace,'fixture','127.0.0.1',timeout=1)
            self.assertLess(time.monotonic()-start,3)
            self.assertEqual(self.workspace.snapshot('fixture')['runs'][0]['status'],'failed')

    def test_program_identification_headers_reach_server(self):
        self.policy['scan'].update({'user_agent':'Researcher/fixture','request_headers':{'X-Researcher':'fixture-id'}})
        Client(self.policy).get(self.origin+'/next')
        self.assertEqual(Fixture.last_headers['User-Agent'],'Researcher/fixture')
        self.assertEqual(Fixture.last_headers['X-Researcher'],'fixture-id')


if __name__ == '__main__':
    unittest.main()
