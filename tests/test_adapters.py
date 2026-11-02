import json
import unittest
from expertool.adapters import parse_output
from expertool.workspace import Workspace


def event(**kwargs):
    value = {'template-id': 'fixture-check', 'type': 'http', 'matched-at': 'https://api.example.com/test',
             'info': {'name': 'Fixture finding', 'severity': 'medium'}, 'matcher-status': True}
    value.update(kwargs)
    return value


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(':memory:')
        self.workspace.add_program('demo', {'authorized': True, 'include': ['*.example.com'], 'exclude': ['private.example.com']})

    def tearDown(self):
        self.workspace.close()

    def test_discovery_is_not_claimed_as_live_https(self):
        for format_name, content in [('subfinder', 'api.example.com\n'), ('subfinder-json', '{"host":"api.example.com","sources":["fixture"]}')]:
            records = parse_output(content, format_name)
            self.assertEqual(records[0]['url'], 'dns://api.example.com')
            self.workspace.import_records('demo', records, format_name)
        snapshot = self.workspace.snapshot('demo')
        self.assertEqual(len(snapshot['assets']), 1)
        self.assertEqual(len(snapshot['observations']), 2)

    def test_httpx_metadata_without_raw_capture(self):
        record = {'url': 'https://api.example.com/', 'status_code': 200, 'tech': ['Fixture'],
                  'body': 'fixture-secret', 'request': 'fixture-secret', 'header': {'Set-Cookie': 'fixture-secret'}}
        self.workspace.import_records('demo', parse_output(json.dumps(record), 'httpx'), 'httpx')
        snapshot = self.workspace.snapshot('demo')
        self.assertEqual(snapshot['observations'][0]['metadata']['tech'], ['Fixture'])
        self.assertNotIn('fixture-secret', str(snapshot))
        self.assertEqual(snapshot['findings'], [])

    def test_nuclei_false_match_does_not_become_finding(self):
        for extra in [{'matcher-status': False}, {'error': 'fixture failure'}]:
            result = parse_output(json.dumps(event(**extra)), 'nuclei')
            self.assertEqual(result[0]['findings'], [])

    def test_nuclei_matchers_distinct_and_repeat_import_idempotent(self):
        records = parse_output('\n'.join(json.dumps(event(**{'matcher-name': name})) for name in ['first', 'second']), 'nuclei')
        self.assertEqual(self.workspace.import_records('demo', records, 'nuclei')['findings_added'], 2)
        finding = self.workspace.snapshot('demo')['findings'][0]
        self.workspace.review(finding['id'], 'confirmed')
        self.assertEqual(self.workspace.import_records('demo', records, 'nuclei')['findings_added'], 0)
        self.assertEqual(self.workspace.snapshot('demo')['findings'][0]['state'], 'confirmed')

    def test_nuclei_unknown_severity_retained_without_inflation(self):
        item = event(info={'name': 'Fixture', 'severity': 'unknown'})
        finding = parse_output(json.dumps(item), 'nuclei')[0]['findings'][0]
        self.assertEqual(finding['severity'], 'info')
        self.assertIn('unknown', finding['evidence'])

    def test_out_of_scope_native_batch_is_atomic(self):
        records = parse_output('api.example.com\nprivate.example.com\n', 'subfinder')
        with self.assertRaises(ValueError):
            self.workspace.import_records('demo', records, 'subfinder')
        self.assertEqual(self.workspace.snapshot('demo')['assets'], [])
        self.assertEqual(self.workspace.snapshot('demo')['observations'], [])

    def test_failure_reports_physical_line_number(self):
        with self.assertRaisesRegex(ValueError, 'httpx line 3'):
            parse_output('\n{"url":"https://api.example.com"}\nnot-json', 'httpx')

    def test_unsupported_or_malformed_events_rejected(self):
        for item in [event(type='dns'), event(info=None), event(**{'matcher-status': 'false'}), event(**{'matched-at': 'file:///tmp/test'})]:
            with self.assertRaises(ValueError):
                parse_output(json.dumps(item), 'nuclei')
        with self.assertRaises(ValueError):
            parse_output('{"url":"https://api.example.com","status_code":true}', 'httpx')

    def test_nuclei_raw_secrets_not_copied(self):
        item = event(request='fixture-secret', response='fixture-secret', **{'curl-command': 'fixture-secret', 'extracted-results': ['fixture-secret']})
        self.workspace.import_records('demo', parse_output(json.dumps(item), 'nuclei'), 'nuclei')
        self.assertNotIn('fixture-secret', str(self.workspace.snapshot('demo')))


if __name__ == '__main__':
    unittest.main()
