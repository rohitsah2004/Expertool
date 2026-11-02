import json
from pathlib import Path
import unittest
from unittest.mock import patch

from expertool.execution import Response
from expertool.orchestrator import assess, configuration, parse_nmap, parse_wpscan, fingerprint
from expertool.workspace import Workspace

NMAP = '<nmaprun><host><status state="up"/><address addr="203.0.113.10"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.62"><cpe>cpe:/a:apache:http_server:2.4.62</cpe></service></port></ports><os><osmatch name="Linux" accuracy="93"/></os></host></nmaprun>'


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.workspace=Workspace(':memory:')
        self.policy={'authorized':True,'include':['example.com'],'exclude':[], 'allowed_modes':['active'],
                     'orchestration':{'enabled':True,'external_http':True,'network_authorized_ips':['203.0.113.10/32'],
                                      'nmap_tcp_ports':[80,443], 'nmap_os':True}}
        self.workspace.add_program('fixture',self.policy)
        self.calls=[]

    def tearDown(self):
        self.workspace.close()

    def response(self, wordpress=True):
        body=b'<meta name="generator" content="WordPress 6.7"><link href="/wp-content/style.css">' if wordpress else b'<title>Plain page</title>'
        return Response('https://example.com/',200,{'content-type':'text/html'},[],body,False,'203.0.113.10')

    def process(self,args,timeout,max_bytes,directory,watched=(),env=None):
        self.calls.append(args)
        if args[0]=='nmap':
            Path(args[args.index('-oX')+1]).write_text(NMAP)
        elif args[0]=='whatweb':
            path=next(arg.split('=',1)[1] for arg in args if arg.startswith('--log-json='))
            Path(path).write_text(json.dumps([{'plugins':{'WordPress':{'version':['6.7']}}}]))
        elif args[0]=='wpscan':
            Path(args[args.index('--output')+1]).write_text(json.dumps({'version':{'number':'6.7','vulnerabilities':[]},'plugins':{'fixture-plugin':{'version':{'number':'1.0'},'vulnerabilities':[{'title':'Fixture advisory','id':'fixture-id','references':{'cve':['CVE-FIXTURE']}}]}}}))
        elif args[0]=='searchsploit':
            return json.dumps({'RESULTS_EXPLOIT':[{'Title':'Fixture research','EDB-ID':'12345','Path':'not-copied'}]})
        elif args[0]=='curl':
            return '200'
        return ''

    def run_assessment(self,wordpress=True,process=None):
        with patch('expertool.orchestrator.scan',return_value={'status':'completed','run_id':99}), patch('expertool.orchestrator.Client') as client, patch('expertool.orchestrator.shutil.which',side_effect=lambda name:'/fixture/'+name), patch('expertool.orchestrator.run_process',side_effect=process or self.process), patch('expertool.orchestrator.os.geteuid',return_value=501):
            client.return_value.get.return_value=self.response(wordpress)
            client.return_value.config={'max_seconds':120}
            return assess(self.workspace,'fixture','https://example.com/')

    def test_wordpress_drives_research_and_unguarded_scanners_stay_blocked(self):
        result=self.run_assessment()
        self.assertTrue(result['fingerprint']['wordpress'])
        self.assertFalse(any(c[0]=='wpscan' for c in self.calls))
        self.assertEqual(next(s for s in result['steps'] if s['tool']=='wpscan')['status'],'blocked')
        self.assertTrue(any(c[0]=='searchsploit' for c in self.calls))
        nmap=next(c for c in self.calls if c[0]=='nmap')
        self.assertEqual(nmap[-1],'203.0.113.10')
        self.assertIn('-sV',nmap)
        self.assertNotIn('-O',nmap)
        self.assertNotIn('--script',nmap)
        snapshot=self.workspace.snapshot('fixture')
        self.assertEqual(snapshot['findings'],[])
        self.assertNotIn('not-copied',str(snapshot))
        self.assertIn('requires existing raw-packet',str(snapshot))

    def test_non_wordpress_does_not_launch_wpscan(self):
        def no_wp(args,*rest,**kwargs):
            if args[0]=='whatweb':
                path=next(a.split('=',1)[1] for a in args if a.startswith('--log-json='))
                Path(path).write_text('[{"plugins":{}}]');return ''
            return self.process(args,*rest,**kwargs)
        self.run_assessment(False,no_wp)
        self.assertFalse(any(c[0]=='wpscan' for c in self.calls))

    def test_dry_run_does_not_resolve_or_launch(self):
        with patch('expertool.orchestrator.Client') as client, patch('expertool.orchestrator.run_process') as process:
            plan=assess(self.workspace,'fixture','https://example.com/',dry_run=True)
        self.assertIn('wpscan',plan['conditional'])
        client.assert_not_called();process.assert_not_called()
        self.assertEqual(self.workspace.snapshot('fixture')['runs'],[])

    def test_network_scan_needs_explicit_ip_authorization(self):
        self.policy['orchestration']['network_authorized_ips']=[]
        self.workspace.db.execute('UPDATE programs SET policy=?',(json.dumps(self.policy),));self.workspace.db.commit()
        result=self.run_assessment()
        self.assertFalse(any(c[0]=='nmap' for c in self.calls))
        self.assertIn('not explicitly authorized',str(result))

    def test_scanner_error_does_not_stop_other_tools(self):
        def failure(args,*rest,**kwargs):
            if args[0]=='nmap':raise TimeoutError('fixture timeout')
            return self.process(args,*rest,**kwargs)
        result=self.run_assessment(process=failure)
        self.assertEqual(result['status'],'completed-with-gaps')
        self.assertTrue(any(c[0]=='curl' for c in self.calls))
        self.assertEqual(next(s for s in result['steps'] if s['tool']=='nmap')['status'],'failed')

    def test_external_http_disabled_by_policy(self):
        self.policy['orchestration']['external_http']=False
        self.workspace.db.execute('UPDATE programs SET policy=?',(json.dumps(self.policy),));self.workspace.db.commit()
        self.run_assessment()
        self.assertFalse(any(c[0] in {'whatweb','wpscan'} for c in self.calls))

    def test_xml_and_configuration(self):
        parsed=parse_nmap(NMAP)
        self.assertEqual(parsed[0]['ports'][0]['version'],'2.4.62')
        self.assertEqual(parsed[0]['os_matches'][0]['accuracy'],'93')
        with self.assertRaises(ValueError):parse_nmap('<!ENTITY x "test"><nmaprun/>')
        with self.assertRaises(ValueError):configuration({'orchestration':{'nmap_tcp_ports':'80; echo test'}})
        parsed=parse_wpscan({'version':{'number':'6.7'}})
        self.assertEqual(parsed['components'][0]['version'],'6.7')
        self.assertFalse(fingerprint(self.response(False))['wordpress'])

    def test_network_inventory_continues_when_http_is_down(self):
        with patch('expertool.orchestrator.scan',return_value={'status':'failed','run_id':99}), patch('expertool.orchestrator.Client') as client, patch('expertool.orchestrator.resolve_destination',return_value='203.0.113.10'), patch('expertool.orchestrator.shutil.which',side_effect=lambda name:'/fixture/'+name), patch('expertool.orchestrator.run_process',side_effect=self.process), patch('expertool.orchestrator.os.geteuid',return_value=501):
            client.return_value.get.side_effect=OSError('fixture web service down')
            client.return_value.config={'max_seconds':120}
            result=assess(self.workspace,'fixture','https://example.com/')
        self.assertTrue(any(c[0]=='nmap' for c in self.calls))
        self.assertEqual(result['fingerprint']['http_fingerprint'],'unavailable')

    def test_curl_identification_and_nmap_header_incompatibility(self):
        self.policy['scan']={'request_headers':{'X-Researcher':'fixture-id'},'user_agent':'Researcher/fixture'}
        self.workspace.db.execute('UPDATE programs SET policy=?',(json.dumps(self.policy),));self.workspace.db.commit()
        self.run_assessment()
        self.assertFalse(any(c[0]=='nmap' for c in self.calls))
        curl=next(c for c in self.calls if c[0]=='curl')
        self.assertEqual(curl[1],'-q')
        self.assertIn('X-Researcher: fixture-id',curl)
        self.assertIn('Researcher/fixture',curl)


if __name__=='__main__':
    unittest.main()
