import copy
import hashlib
import http.client
import os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from expertool.curated import load_manifest,TemplateDenied
from expertool.scanner_profiles import build_command,normalize_output,scanner_settings
from expertool.scanners import run_scanner
from expertool.workspace import Workspace


class Target(BaseHTTPRequestHandler):
    hits=[]
    def log_message(self,*args):pass
    def do_GET(self):
        Target.hits.append(self.path)
        body=b'EXPERTOOL_FIXTURE_MARKER'
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


PYTHON_TOOL='''#!INTERPRETER
import base64,json,os,pathlib,sys,http.client,urllib.parse
args=sys.argv[1:];tool=pathlib.Path(sys.argv[0]).name
assert 'WPSCAN_API_TOKEN' not in os.environ
proxy=os.environ['HTTP_PROXY']
if tool=='httpx':
 fd=args[args.index('-config')+1];proxy=json.loads(pathlib.Path(fd).read_text())['proxy']
if tool=='nuclei':
 fd=args[args.index('-proxy')+1];proxy=pathlib.Path(fd).read_text().strip()
url=args[args.index('-u')+1]
p=urllib.parse.urlsplit(proxy);target=urllib.parse.urlsplit(url)
credentials=urllib.parse.unquote(p.username)+':'+urllib.parse.unquote(p.password)
connection=http.client.HTTPConnection(p.hostname,p.port,timeout=2)
headers={'Proxy-Authorization':'Basic '+base64.b64encode(credentials.encode()).decode()}
connection.request('GET',url,headers=headers);r=connection.getresponse();r.read();connection.close()
if r.status!=200:sys.exit(2)
if tool=='httpx':
 print(json.dumps({'url':url,'status_code':200,'title':'fixture','tech':['WordPress'],'hash':{'body_sha256':'abc'}}))
else:
 print(json.dumps({'template-id':'fixture-check','type':'http','matched-at':url,'info':{'name':'Fixture candidate','severity':'info'},'matcher-status':True,'request':'Authorization: Bearer never-store-fixture','response':'fixture-response-body'}))
'''

RUBY_TOOL='''#!/usr/bin/env ruby
require 'json'
require 'net/http'
raise 'inherited-token' if ENV.key?('WPSCAN_API_TOKEN')
a=ARGV.dup
is_wp=File.basename($0)=='wpscan'
url=is_wp ? a[a.index('--url')+1] : a[-1]
uri=URI(url)
proxy=a[a.index('--proxy')+1]
proxy=URI(proxy.start_with?('http') ? proxy : 'http://'+proxy)
auth=a[a.index(is_wp ? '--proxy-auth' : '--proxy-user')+1].split(':',2)
unless is_wp
 $PROXY_PASS = [[auth[1]]].to_s
 raise 'bad-proxy-password' unless $PROXY_PASS == auth[1]
 raise 'bad-approved-dns' unless Resolv.getaddress(uri.host) == uri.host
 begin
  Resolv.getaddress('unapproved.invalid')
  raise 'dns-bypass'
 rescue Resolv::ResolvError
 end
end
http=Net::HTTP::Proxy(proxy.host,proxy.port,auth[0],auth[1]).new(uri.host,uri.port)
r=http.get(uri.request_uri)
exit 2 unless r.code=='200'
if is_wp
 output=a[a.index('--output')+1]
 result={'version'=>{'number'=>'6.7'},'plugins'=>{'fixture'=>{'version'=>{'number'=>'1.0'},'vulnerabilities'=>[{'id'=>'fixture-advisory','title'=>'Controlled fixture advisory'}]}}}
else
 output=a.find{|v|v.start_with?('--log-json=')}.split('=',2)[1]
 result=[{'http_status'=>200,'plugins'=>{'WordPress'=>{'version'=>['6.7']}}}]
end
File.write(output,JSON.generate(result))
exit 5 if is_wp
'''


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Target)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}/'

    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.workspace=Workspace(':memory:')
        self.policy={'authorized':True,'include':['127.0.0.1'],'exclude':[],'allowed_modes':['active'],
          'automation':{'allowed':True,'tools':['http','httpx','nuclei','whatweb','wpscan']},
          'scan':{'allow_private':True,'ports':[self.server.server_port],'rate_per_second':10,'timeout':2},
          'scanners':{'enabled':['httpx','nuclei','whatweb','wpscan'],'timeout':4}}
        self.template={'id':'fixture-check','info':{'name':'Fixture','author':'fixture','severity':'info','tags':['tech']},
                       'http':[{'method':'GET','path':['{{BaseURL}}'],'matchers':[{'type':'word','words':['EXPERTOOL_FIXTURE_MARKER']}]}]}
        self.manifest=self.write_manifest(self.template)
        self.policy['scanners']['nuclei']={'manifest':str(self.manifest),'allowed_tags':['tech'],'allowed_severities':['info']}
        self.workspace.add_program('lab',self.policy);Target.hits=[]

    def tearDown(self):self.workspace.close();self.temp.cleanup()

    def write_manifest(self,template):
        file=self.root/'template.json';file.write_text(json.dumps(template))
        manifest=self.root/'manifest.json';manifest.write_text(json.dumps({'templates':[{'path':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}]}))
        return manifest

    def update(self):self.workspace.update_program('lab',self.policy)

    def test_missing_tool_is_skipped_and_recorded(self):
        with patch('expertool.scanners.find_executable',return_value=None):result=run_scanner(self.workspace,'lab','httpx',self.url)
        self.assertEqual(result['status'],'skipped');self.assertEqual(self.workspace.snapshot('lab')['runs'][0]['status'],'skipped')

    def test_disabled_and_disallowed_tools_are_blocked(self):
        self.policy['scanners']['enabled']=[];self.update()
        self.assertEqual(run_scanner(self.workspace,'lab','httpx',self.url)['status'],'blocked')
        self.policy['scanners']['enabled']=['httpx'];self.policy['automation']['tools']=['http'];self.update()
        with patch('expertool.scanners.launch') as launch:
            self.assertEqual(run_scanner(self.workspace,'lab','httpx',self.url)['status'],'blocked')
            launch.assert_not_called()

    def test_tampered_pin_and_intrusive_tags_are_blocked(self):
        (self.root/'template.json').write_text('{}')
        with self.assertRaises(TemplateDenied):load_manifest(self.manifest,self.policy,self.url,['tech'],['info'])
        for tag in ['dos','fuzz','bruteforce','intrusive']:
            value=copy.deepcopy(self.template);value['info']['tags']=['tech',tag];self.write_manifest(value)
            with self.assertRaises(TemplateDenied):load_manifest(self.manifest,self.policy,self.url,['tech'],['info'])

    def test_unsafe_template_features_and_paths_are_blocked(self):
        mutations=[lambda t:t.update(code=[{}]),lambda t:t['http'][0].update(method='POST'),
                   lambda t:t['http'][0].update(raw=['GET / HTTP/1.1']),lambda t:t['http'][0].update(path=['https://outside.invalid/']),
                   lambda t:t['http'][0].update(path=['{{RootURL}}/x?url=http://outside.invalid/']),lambda t:t['http'][0].update(payloads={'x':['bad']})]
        for mutation in mutations:
            value=copy.deepcopy(self.template);mutation(value);self.write_manifest(value)
            with self.assertRaises((TemplateDenied,ValueError)):load_manifest(self.manifest,self.policy,self.url,['tech'],['info'])

    def test_severity_and_manifest_path_restrictions(self):
        with self.assertRaises(TemplateDenied):load_manifest(self.manifest,self.policy,self.url,['tech'],['low'])
        self.manifest.write_text(json.dumps({'templates':[{'path':'../outside.json','sha256':'a'*64}]}))
        with self.assertRaises((TemplateDenied,OSError)):load_manifest(self.manifest,self.policy,self.url,['tech'],['info'])

    def test_nuclei_command_is_curated_and_non_intrusive(self):
        loaded=load_manifest(self.manifest,self.policy,self.url,['tech'],['info'])
        args,_=build_command('nuclei',self.url,self.root,{'rate_per_second':1,'user_agent':'Fixture','request_headers':{}},2,loaded)
        self.assertIn('-t',args);self.assertIn('-no-interactsh',args);self.assertIn('-omit-raw',args)
        for flag in ['-code','-headless','-dast','-automatic-scan','-update','-update-templates']:self.assertNotIn(flag,args)
        for tool in ['whatweb','wpscan']:
            args,_=build_command(tool,self.url,self.root,{'rate_per_second':1,'user_agent':'Fixture','request_headers':{}},2)
            self.assertFalse(any(flag in args for flag in ['--passwords','--usernames','--enumerate','--force']))

    def test_saved_formats_still_normalize_and_redact(self):
        records=normalize_output('httpx',json.dumps({'url':self.url,'status_code':200,'hash':{'body_sha256':'abc'}}),self.url)
        self.assertEqual(records[0]['metadata']['hash']['body_sha256'],'abc')
        record=normalize_output('nuclei',json.dumps({'type':'http','template-id':'fixture-check','matched-at':self.url,'info':{'name':'fixture','severity':'info'},'request':'secret-request','response':'secret-response'}),self.url)[0]
        self.assertNotIn('secret-request',str(record));self.assertNotIn('secret-response',str(record))

    def test_unproxied_success_output_is_not_trusted(self):
        with patch('expertool.scanners.find_executable',return_value='/fixture/httpx'),patch('expertool.scanners.launch',return_value=''):
            result=run_scanner(self.workspace,'lab','httpx',self.url)
        self.assertEqual(result['status'],'blocked');self.assertEqual(self.workspace.snapshot('lab')['assets'],[])

    def test_runtime_failure_is_recorded(self):
        with patch('expertool.scanners.find_executable',return_value='/fixture/httpx'),patch('expertool.scanners.launch',side_effect=ValueError('fixture fail')):
            result=run_scanner(self.workspace,'lab','httpx',self.url)
        self.assertEqual(result['status'],'failed');self.assertEqual(self.workspace.snapshot('lab')['runs'][0]['status'],'failed')

    def test_invalid_credential_url_never_reaches_storage_or_launcher(self):
        with patch('expertool.scanners.launch') as launch:
            result=run_scanner(self.workspace,'lab','httpx','http://fixture-user:fixture-private-password@127.0.0.1/')
            launch.assert_not_called()
        self.assertEqual(result['status'],'blocked')
        dump='\n'.join(self.workspace.db.iterdump())
        self.assertNotIn('fixture-private-password',dump);self.assertNotIn('fixture-user',dump)

    def test_credentials_cannot_be_embedded_in_curated_templates(self):
        value=copy.deepcopy(self.template);value['info']['description']='Authorization: Bearer fixture-private-value'
        self.write_manifest(value)
        with self.assertRaises(TemplateDenied):load_manifest(self.manifest,self.policy,self.url,['tech'],['info'])

    def proxied_request(self,proxy):
        connection=http.client.HTTPConnection(proxy.endpoint.host,proxy.endpoint.port,timeout=2)
        try:
            connection.request('GET',self.url,headers={'Proxy-Authorization':proxy.endpoint.authorization})
            response=connection.getresponse();response.read();return response.status
        finally:connection.close()

    def test_out_of_scope_output_is_blocked_atomically(self):
        def launch(tool,binary,args,directory,output,proxy,*rest):
            self.assertEqual(self.proxied_request(proxy),200)
            return json.dumps({'url':'http://outside.example/','status_code':200})
        with patch('expertool.scanners.find_executable',return_value='/fixture/httpx'),patch('expertool.scanners.launch',side_effect=launch):
            result=run_scanner(self.workspace,'lab','httpx',self.url)
        self.assertEqual(result['status'],'blocked');self.assertEqual(self.workspace.snapshot('lab')['assets'],[])

    def test_policy_change_revokes_scanner_session(self):
        def launch(tool,binary,args,directory,output,proxy,*rest):
            self.assertEqual(self.proxied_request(proxy),200)
            changed=copy.deepcopy(self.policy);changed['scanners']['enabled']=[]
            self.workspace.update_program('lab',changed)
            self.assertEqual(self.proxied_request(proxy),403)
            return json.dumps({'url':self.url,'status_code':200})
        with patch('expertool.scanners.find_executable',return_value='/fixture/httpx'),patch('expertool.scanners.launch',side_effect=launch):
            result=run_scanner(self.workspace,'lab','httpx',self.url)
        self.assertEqual(result['status'],'blocked');self.assertEqual(self.workspace.snapshot('lab')['assets'],[])

    def test_unapproved_template_output_is_blocked(self):
        def launch(tool,binary,args,directory,output,proxy,*rest):
            self.assertEqual(self.proxied_request(proxy),200)
            return json.dumps({'type':'http','template-id':'not-approved','matched-at':self.url,'info':{'name':'Fixture','severity':'info'}})
        with patch('expertool.scanners.find_executable',return_value='/fixture/nuclei'),patch('expertool.scanners.launch',side_effect=launch):
            result=run_scanner(self.workspace,'lab','nuclei',self.url)
        self.assertEqual(result['status'],'blocked');self.assertEqual(self.workspace.snapshot('lab')['findings'],[])

    def test_proxy_credentials_are_memory_only(self):
        def guarded(args,timeout,max_bytes,directory,watched,**kwargs):
            endpoint=kwargs['endpoint']
            self.assertNotIn(endpoint.token,str(args))
            descriptor=kwargs['pass_fds'][0]
            self.assertIn(endpoint.token,Path('/dev/fd/'+str(descriptor)).read_text())
            for file in Path(directory).rglob('*'):
                if file.is_file():self.assertNotIn(endpoint.token,file.read_text(errors='replace'))
            class Session:pass
            session=Session();session.endpoint=endpoint
            self.assertEqual(self.proxied_request(session),200)
            return json.dumps({'type':'http','template-id':'fixture-check','matched-at':self.url,'info':{'name':'Fixture','severity':'info'}})
        with patch('expertool.scanners.find_executable',return_value='/fixture/nuclei'),patch('expertool.scanners.run_guarded',side_effect=guarded):
            result=run_scanner(self.workspace,'lab','nuclei',self.url)
        self.assertEqual(result['status'],'completed',result)

    def test_httpx_explicit_proxy_config_is_memory_only(self):
        def guarded(args,timeout,max_bytes,directory,watched,**kwargs):
            endpoint=kwargs['endpoint']
            self.assertNotIn(endpoint.token,str(args))
            path=args[args.index('-config')+1]
            config=json.loads(Path(path).read_text())
            self.assertIn(endpoint.token,config['proxy'])
            for file in Path(directory).rglob('*'):
                if file.is_file():self.assertNotIn(endpoint.token,file.read_text(errors='replace'))
            class Session:pass
            session=Session();session.endpoint=endpoint
            self.assertEqual(self.proxied_request(session),200)
            return json.dumps({'url':self.url,'status_code':200})
        with patch('expertool.scanners.find_executable',return_value='/fixture/httpx'),patch('expertool.scanners.run_guarded',side_effect=guarded):
            result=run_scanner(self.workspace,'lab','httpx',self.url)
        self.assertEqual(result['status'],'completed',result)

    def test_pipeline_uses_httpx_wordpress_signal_and_preserves_blocked_status(self):
        from expertool.execution import Response
        from expertool.orchestrator import assess
        self.policy['orchestration']={'enabled':True,'tools':['httpx','wpscan','nuclei']}
        self.update();calls=[]
        def scanner(workspace,program,tool,target,**kwargs):
            calls.append(tool)
            run=workspace.start_run(program,tool,{})
            if tool=='httpx':workspace.import_records(program,[{'url':target,'metadata':{'live_run_id':run,'tech':['WordPress']}}],'mock-live')
            workspace.finish_run(run,'completed',{})
            return {'run_id':run,'tool':tool,'status':'completed-with-blocks' if tool=='nuclei' else 'completed'}
        with patch('expertool.orchestrator.scan',return_value={'run_id':0,'status':'completed'}),patch('expertool.orchestrator.Client') as client,patch('expertool.scanners.run_scanner',side_effect=scanner):
            client.return_value.get.return_value=Response(self.url,200,{},[],b'plain page',False,'127.0.0.1')
            client.return_value.config={'max_seconds':120}
            result=assess(self.workspace,'lab',self.url)
        self.assertEqual(calls,['httpx','wpscan','nuclei'])
        self.assertTrue(result['fingerprint']['wordpress'])
        self.assertEqual(result['status'],'completed-with-gaps')

    @unittest.skipUnless(platform.system()=='Darwin' and shutil.which('sandbox-exec'),'real isolation backend')
    def test_mock_httpx_and_nuclei_binaries_use_real_guard(self):
        for tool in ['httpx','nuclei']:
            binary=self.root/tool;binary.write_text(PYTHON_TOOL.replace('INTERPRETER',str(Path(sys.executable).resolve())));binary.chmod(0o700)
            with patch('expertool.scanners.find_executable',return_value=str(binary)),patch.dict(os.environ,{'WPSCAN_API_TOKEN':'fixture-do-not-inherit'}):
                result=run_scanner(self.workspace,'lab',tool,self.url)
            self.assertEqual(result['status'],'completed',result)
            self.assertGreater(result['allowed_requests'],0)
        snapshot=self.workspace.snapshot('lab')
        self.assertEqual(snapshot['findings'][0]['state'],'candidate')
        self.assertIn('matched_url',snapshot['findings'][0]['evidence'])
        self.assertNotIn('never-store-fixture',str(snapshot));self.assertNotIn('fixture-response-body',str(snapshot))

    @unittest.skipUnless(platform.system()=='Darwin' and shutil.which('ruby'),'Ruby isolation backend')
    def test_mock_whatweb_and_wpscan_binaries_use_real_guard(self):
        real_ruby=shutil.which('ruby')
        for tool in ['whatweb','wpscan']:
            binary=self.root/tool;binary.write_text(RUBY_TOOL);binary.chmod(0o700)
            with patch('expertool.scanners.find_executable',side_effect=lambda name:str(binary) if name==tool else real_ruby),patch.dict(os.environ,{'WPSCAN_API_TOKEN':'fixture-do-not-inherit'}):
                result=run_scanner(self.workspace,'lab',tool,self.url)
            self.assertEqual(result['status'],'completed',result)
        findings=self.workspace.snapshot('lab')['findings']
        self.assertEqual(findings[0]['state'],'candidate');self.assertIn('wpscan.',findings[0]['check_id'])


if __name__=='__main__':unittest.main()
