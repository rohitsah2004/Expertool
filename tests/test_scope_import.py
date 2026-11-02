import copy
import unittest
from unittest.mock import patch

from expertool.execution import Client, checked_url, settings
from expertool.scope import validate_program, matches
from expertool.scope_import import convert_scope
from expertool.workspace import Workspace


def reviewed(draft):
    policy=copy.deepcopy(draft)
    policy['authorized']=True
    policy['scope_review']['complete']=True
    policy['allowed_modes']=['active','passive']
    policy['automation']={'allowed':True,'tools':['http','curl']}
    return policy


def export(assets):
    return {'provider':'bugcrowd','complete':True,'assets':assets}


class ScopeImportTests(unittest.TestCase):
    def setUp(self):
        self.draft=convert_scope(export([
            {'identifier':'https://api.example.com/public/*','in_scope':True},
            {'identifier':'https://api.example.com/public/private','in_scope':False},
            {'identifier':'*.example.net','in_scope':True},
            {'identifier':'excluded.example.net','in_scope':False}]))
        self.policy=reviewed(self.draft)

    def test_draft_cannot_be_registered_without_review(self):
        for policy in [self.draft,dict(self.draft,authorized=True)]:
            with self.assertRaises(ValueError):validate_program(policy)
        self.assertFalse(self.draft['automation']['allowed'])
        self.assertEqual(len(self.draft['scope_review']['source_sha256']),64)

    def test_path_scheme_port_and_exclusion_boundaries(self):
        self.assertEqual(checked_url(self.policy,'https://api.example.com/public/item'),'https://api.example.com/public/item')
        for url in ['https://api.example.com/other','https://api.example.com/publicity','https://api.example.com/public/private/child',
                    'http://api.example.com/public/item','https://api.example.com:8443/public/item','https://excluded.example.net/',
                    'https://example.net/','https://api.example.com/public/%252e%252e/private']:
            with self.assertRaises(ValueError,msg=url):checked_url(self.policy,url)
        self.assertEqual(checked_url(self.policy,'https://a.example.net/'),'https://a.example.net/')

    def test_url_without_wildcard_does_not_grant_subtree(self):
        policy=reviewed(convert_scope(export([{'identifier':'https://example.com/exact','in_scope':True}])))
        checked_url(policy,'https://example.com/exact')
        with self.assertRaises(ValueError):checked_url(policy,'https://example.com/exact/child')

    def test_hackerone_structured_scopes_and_exclusions(self):
        document={'data':[{'type':'structured-scope','attributes':{'asset_type':'URL','asset_identifier':'https://api.example.com/public/*',
            'eligible_for_submission':True,'eligible_for_bounty':False,'instruction':'Automation requires a researcher header'}}]}
        draft=convert_scope(document,'hackerone',{'data':[]})
        self.assertEqual(draft['scope_review']['blockers'],[])
        self.assertIn('Automation requires',str(draft['scope_review']['instructions']))
        self.assertFalse(draft['authorized'])
        blocked=convert_scope(document,'hackerone')
        self.assertIn('not provided',str(blocked['scope_review']['blockers']))

    def test_missing_pages_unsupported_assets_and_flags_fail_closed(self):
        document={'links':{'next':'https://api.example.invalid/page/2'},'data':[
            {'type':'structured-scope','attributes':{'asset_type':'ANDROID_APP_ID','asset_identifier':'com.fixture.app','eligible_for_submission':True}}]}
        draft=convert_scope(document,'hackerone',{'data':[]})
        policy=reviewed(draft)
        with self.assertRaises(ValueError):validate_program(policy)
        self.assertIn('another page',str(draft))
        with self.assertRaises(ValueError):convert_scope(export([{'identifier':'example.com','in_scope':'true'}]))

    def test_ipv4_cidr_boundary(self):
        self.assertTrue(matches('192.0.2.15','192.0.2.0/24'))
        self.assertFalse(matches('192.0.3.15','192.0.2.0/24'))
        self.assertFalse(matches('api.example.com','192.0.2.0/24'))

    def test_automation_denied_before_network(self):
        self.policy['automation']['allowed']=False
        with patch('expertool.execution.socket.getaddrinfo') as dns:
            with self.assertRaisesRegex(ValueError,'prohibits'):Client(self.policy)
            dns.assert_not_called()
        self.policy['automation']={'allowed':True,'tools':['curl']}
        with self.assertRaisesRegex(ValueError,'http'):settings(self.policy)

    def test_offline_import_does_not_broaden_url_scope(self):
        workspace=Workspace(':memory:')
        try:
            workspace.add_program('reviewed',self.policy)
            with self.assertRaises(ValueError):workspace.import_records('reviewed',[{'url':'https://api.example.com/other'}],'fixture')
            self.assertEqual(workspace.snapshot('reviewed')['assets'],[])
        finally:workspace.close()

    def test_header_injection_and_transport_headers_rejected(self):
        for headers in [{'Host':'evil.example'},{'X-Researcher':'name\r\nHost: evil.example'},{'Authorization':'Bearer fixture'}]:
            policy=copy.deepcopy(self.policy)
            policy['scan']={'request_headers':headers}
            with self.assertRaises(ValueError):settings(policy)
        policy=copy.deepcopy(self.policy)
        policy['scan']={'user_agent':'Researcher/fixture','request_headers':{'X-Researcher':'fixture'}}
        self.assertEqual(settings(policy)['request_headers']['X-Researcher'],'fixture')

    def test_excluded_resolved_ip_is_blocked_before_connection(self):
        self.policy['exclude'].append('8.8.8.0/24')
        answers=[(2,1,6,'',('8.8.8.8',443))]
        with patch('expertool.execution.socket.getaddrinfo',return_value=answers),patch('expertool.execution.socket.create_connection') as connect:
            with self.assertRaisesRegex(ValueError,'explicitly out of scope'):
                Client(self.policy).get('https://api.example.com/public/item')
            connect.assert_not_called()


if __name__=='__main__':unittest.main()
