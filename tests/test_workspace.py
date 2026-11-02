import unittest
from expertool.workspace import Workspace, inspect_headers, markdown_report


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(':memory:')
        self.policy = {'authorized': True, 'include': ['*.example.com'], 'exclude': ['private.example.com']}
        self.workspace.add_program('demo', self.policy)

    def tearDown(self):
        self.workspace.close()

    def test_atomic_scope_rejection(self):
        with self.assertRaises(ValueError):
            self.workspace.import_records('demo', [{'url': 'api.example.com'}, {'url': 'private.example.com'}], 'test')
        self.assertEqual(self.workspace.snapshot('demo')['assets'], [])

    def test_deduplication_review_and_program_isolation(self):
        records = inspect_headers([{'url': 'https://api.example.com/', 'headers': {}}])
        first = self.workspace.import_records('demo', records, 'test')
        self.assertEqual(first['findings_added'], 2)
        second = self.workspace.import_records('demo', records, 'test')
        self.assertEqual(second['findings_added'], 0)
        self.assertEqual(second['assets_added'], 0)
        finding = self.workspace.snapshot('demo')['findings'][0]
        self.assertEqual(finding['state'], 'candidate')
        self.workspace.review(finding['id'], 'dismissed')
        self.workspace.import_records('demo', records, 'test')
        self.assertIn('dismissed', markdown_report(self.workspace.snapshot('demo')))
        self.workspace.add_program('other', self.policy)
        self.assertEqual(self.workspace.snapshot('other')['findings'], [])
        self.assertEqual(self.workspace.import_records('other', records, 'test')['findings_added'], 2)

    def test_header_values_are_not_persisted(self):
        records = inspect_headers([{'url': 'https://api.example.com/', 'headers': {'Set-Cookie': 'secret-fixture-only'}}])
        self.workspace.import_records('demo', records, 'test')
        self.assertNotIn('secret-fixture-only', str(self.workspace.snapshot('demo')))

    def test_http_does_not_get_https_hsts_check(self):
        result = inspect_headers([{'url': 'http://api.example.com/', 'headers': {'X-Content-Type-Options': 'nosniff'}}])
        self.assertEqual(result[0]['findings'], [])

    def test_duplicate_header_case_rejected(self):
        with self.assertRaises(ValueError):
            inspect_headers([{'url': 'api.example.com', 'headers': {'X-Test': 'a', 'x-test': 'b'}}])

    def test_invalid_finding_batch_is_atomic(self):
        with self.assertRaises(ValueError):
            self.workspace.import_records('demo', [{'url': 'api.example.com'}, {'url': 'www.example.com', 'findings': [{}]}], 'test')
        self.assertEqual(self.workspace.snapshot('demo')['assets'], [])


if __name__ == '__main__':
    unittest.main()
