import unittest
from expertool.__main__ import plan, matches, hostname, load_catalog, ROOT


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.program = {'authorized': True, 'include': ['*.example.com'],
                        'exclude': ['private.example.com'], 'allowed_modes': ['passive']}

    def test_exclusion_and_suffix_boundaries(self):
        for target in ['private.example.com', 'example.com', 'evil-example.com', 'api.example.com.evil.test']:
            with self.assertRaises(ValueError):
                plan(self.program, target, [])
        self.assertTrue(matches('api.example.com', '*.example.com'))

    def test_ambiguous_scope_rejected(self):
        for target in ['https://example.com/private', 'https://example.com:8443', 'https://user@example.com']:
            with self.assertRaises(ValueError):
                hostname(target)

    def test_authorization_required(self):
        self.program['authorized'] = False
        with self.assertRaises(ValueError):
            plan(self.program, 'api.example.com', [])

    def test_modes_do_not_silently_enable_active_checks(self):
        result = plan(self.program, 'api.example.com', [{'mode': 'active'}])
        self.assertEqual(result['tasks'][0]['status'], 'blocked-by-program-policy')

    def test_seed_catalog_valid(self):
        self.assertGreater(len(load_catalog(ROOT / 'data/techniques.json')), 10)


if __name__ == '__main__':
    unittest.main()
