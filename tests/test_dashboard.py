import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from expertool.dashboard import DashboardServer
from expertool.workspace import Workspace


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.directory.name) / 'ui.db')
        workspace = Workspace(cls.path)
        workspace.add_program('demo', {'authorized': True, 'include': ['*.example.com'], 'exclude': []})
        workspace.add_program('other', {'authorized': True, 'include': ['*.example.com'], 'exclude': []})
        workspace.import_records('demo', [{'url': 'https://api.example.com/', 'findings': [
            {'check_id': 'fixture', 'title': '<script>fixture</script>', 'severity': 'info', 'evidence': 'Fixture evidence'}]}], 'test')
        workspace.close()
        cls.server = DashboardServer(cls.path, 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.directory.cleanup()

    def request(self, path, data=None, headers=None):
        raw = None if data is None else json.dumps(data).encode()
        try:
            return urlopen(Request(self.base+path, data=raw, headers=headers or {}), timeout=5)
        except HTTPError as error:
            error.close()
            raise

    def test_assets_and_api(self):
        for path in ['/', '/app.js', '/style.css', '/api/programs', '/api/snapshot?program=demo']:
            with self.request(path) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
                self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        with self.request('/api/snapshot?program=other') as response:
            self.assertEqual(json.load(response)['findings'], [])

    def test_review_requires_origin_and_token(self):
        with self.assertRaises(HTTPError) as error:
            self.request('/api/review', {'program':'demo','id':1,'state':'confirmed'}, {'Content-Type':'application/json'})
        self.assertEqual(error.exception.code, 403)

    def test_review_persists_and_wrong_program_rejected(self):
        headers = {'Origin':self.base, 'X-Expertool-Token':self.server.token, 'Content-Type':'application/json'}
        with self.request('/api/review', {'program':'demo','id':1,'state':'confirmed'}, headers):
            pass
        workspace = Workspace(self.path)
        self.assertEqual(workspace.snapshot('demo')['findings'][0]['state'], 'confirmed')
        workspace.close()
        with self.assertRaises(HTTPError) as error:
            self.request('/api/review', {'program':'other','id':1,'state':'dismissed'}, headers)
        self.assertEqual(error.exception.code, 400)

    def test_host_origin_and_cross_site_rejected(self):
        for headers in [{'Host':'evil.example'}, {'Origin':'https://evil.example'}, {'Sec-Fetch-Site':'cross-site'}]:
            with self.assertRaises(HTTPError) as error:
                self.request('/api/session', headers=headers)
            self.assertEqual(error.exception.code, 403)

    def test_no_arbitrary_file_serving(self):
        with self.assertRaises(HTTPError) as error:
            self.request('/../workspace.py')
        self.assertEqual(error.exception.code, 404)

    def test_markdown_download(self):
        with self.request('/api/report?program=demo') as response:
            self.assertIn('attachment', response.headers['Content-Disposition'])
            self.assertIn(b'Fixture evidence', response.read())


if __name__ == '__main__':
    unittest.main()
