"""Opt-in real vendor compatibility tests; only owned loopback fixtures receive traffic."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import unittest
from expertool.workspace import Workspace
from expertool.scanners import run_scanner

ENABLED=os.environ.get('EXPERTOOL_REAL_SCANNERS')=='1'

class WordPressFixture(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_HEAD(self):self.respond(False)
    def do_GET(self):self.respond(True)
    def respond(self,body):
        content=b'<html><head><meta name="generator" content="WordPress 6.7" /></head><body><link href="/wp-content/themes/twentytwentyfive/style.css"/>Owned fixture</body></html>'
        status=200 if self.path=='/' else 404
        if self.path=='/.git/config':status=200;content=b'[core]\nrepositoryformatversion = 0\nbare = false\n'
        self.send_response(status);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(content)));self.end_headers()
        if body:self.wfile.write(content)

@unittest.skipUnless(ENABLED and platform.system()=='Darwin','opt-in real scanner compatibility test')
class RealScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),WordPressFixture)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.workspace=Workspace(str(self.root/'workspace.db'))
        self.policy=json.loads(Path('examples/scanner-lab-program.json').read_text())
        self.policy['scan'].update(ports=[self.server.server_port],max_seconds=45,max_requests=20)
        self.policy['scanners']['timeout']=45
        self.url=f'http://127.0.0.1:{self.server.server_port}/'
    def tearDown(self):self.workspace.close();self.temp.cleanup()
    def run_tool(self,tool):
        if not shutil.which(tool):self.skipTest('Install '+tool+' explicitly first')
        self.workspace.add_program('real-fixture',self.policy)
        result=run_scanner(self.workspace,'real-fixture',tool,self.url)
        self.assertIn(result['status'],{'completed','completed-with-blocks'},result)
        self.assertGreater(result['allowed_requests'],0)
        return result
    def test_httpx(self):self.run_tool('httpx')
    def test_whatweb(self):self.run_tool('whatweb')
    def test_nuclei_yaml_exposure(self):
        if not importlib.util.find_spec('yaml'):self.skipTest('Optional PyYAML required')
        from expertool.template_import import import_templates
        self.policy['scanners']['nuclei'].update(allowed_tags=['exposure'],allowed_severities=['medium'])
        imported=import_templates(['examples/nuclei/exposed-git-config.yaml'],self.root/'bundle',self.policy,self.url)
        self.policy['scanners']['nuclei']['manifest']=imported['manifest']
        result=self.run_tool('nuclei')
        self.assertEqual(result['findings_added'],1)
        finding=self.workspace.snapshot('real-fixture')['findings'][0]
        self.assertEqual(finding['state'],'candidate');self.assertEqual(finding['severity'],'medium')
    def test_wpscan(self):
        database=os.environ.get('EXPERTOOL_WPSCAN_DATABASE')
        if not database:self.skipTest('Provide an explicitly downloaded offline WPScan database')
        self.policy['scanners']['wpscan_database']=database
        self.run_tool('wpscan')
        events=self.workspace.snapshot('real-fixture')['egress']
        self.assertTrue(all(row['host']=='127.0.0.1' for row in events if row['decision']=='allowed'))
