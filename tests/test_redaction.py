import copy
import json
from pathlib import Path
import random
import string
import unittest
from urllib.parse import parse_qsl,urlsplit
import expertool.redaction as r

class RedactionTests(unittest.TestCase):
    def setUp(self):
        with r._LOCK:self.previous=copy.copy(r._SECRETS);r._SECRETS.clear()
    def tearDown(self):
        with r._LOCK:r._SECRETS.clear();r._SECRETS.update(self.previous)
    def test_fixture_cases(self):
        cases=json.loads(Path('tests/fixtures/redaction-test.json').read_text())['cases']
        self.assertGreaterEqual(len(cases),40)
        for case in cases:
            with self.subTest(case=case['name']):
                with r._LOCK:r._SECRETS.clear()
                r.register_credentials(case.get('register',{}))
                kind=case['kind']
                actual=(r.sanitize(case['input']) if kind=='object' else r.sanitize_output(case['input']) if kind=='output' else r.redact_text(case['input'],content_type='application/x-www-form-urlencoded') if kind=='form' else r.redact_text(case['input']))
                self.assertEqual(actual,case['expected'])
    def test_json_property_framing_and_literal_types(self):
        r.register_credentials({'Cookie':'debug=true; lang=en-US','Authorization':'123456789012'})
        rng=random.Random(103)
        def value(depth):
            if not depth:return rng.choice([True,False,None,0,123456789012,1.25,'en-US','description mentioning token'])
            choices=[value(depth-1) for _ in range(3)]
            return rng.choice([choices,{'nested':choices,'X-CSRF-Token':'fixture','csrf_required':True}])
        for _ in range(250):
            document={'is_admin':True,'locale':'en-US','count':123456789012,'payload':value(3)}
            source=json.dumps(document)
            for cleaner in (r.redact_text,r.sanitize_output):
                cleaned=json.loads(cleaner(source))
                self.assertIs(cleaned['is_admin'],True);self.assertEqual(cleaned['count'],123456789012);self.assertEqual(cleaned['locale'],'en-US')
                self.assertEqual(cleaned,r.sanitize(document))
    def test_registration_filters_cookie_names_entropy_and_literals(self):
        r.register_credentials({'Cookie':'debug=true; lang=en-US; digits=0000000000012; region=en-US-posix-locale; note=longordinarywordwithoutdigits'})
        self.assertEqual(len(r._SECRETS),0)
        r.register_credentials({'Cookie':'session_id=lowentropybutlong; opaque=R7uQ91mZ4vA0kL8cD2sX','User-Agent':'not-a-credential-at-all'})
        self.assertIn('lowentropybutlong',r._SECRETS);self.assertIn('R7uQ91mZ4vA0kL8cD2sX',r._SECRETS)
        self.assertNotIn('not-a-credential-at-all',r._SECRETS)
        self.assertNotIn('lowentropybutlong',r.redact_text('value: lowentropybutlong'))
    def test_cache_bounds_and_access_lru(self):
        for n in range(r.MAX_SECRETS):r.register_credentials({'Authorization':f'credential-{n:04d}-Abc123XYZ'})
        first=next(iter(r._SECRETS));self.assertEqual(r.redact_text(first),r.REDACTED)
        r.register_credentials({'Authorization':'latest-fixture-credential-2026'})
        self.assertIn(first,r._SECRETS);self.assertLessEqual(len(r._SECRETS),r.MAX_SECRETS)
        for n in range(40):r.register_credentials({'Authorization':str(n)+'z'*4000})
        self.assertLessEqual(sum(r._SECRETS.values()),r.MAX_REGISTRY_BYTES)
        r.register_credentials({'Authorization':'x'*5000})
        self.assertNotIn('x'*5000,r._SECRETS)
    def test_registered_boundaries_and_typed_json_literals(self):
        secret='boundary-credential-2026'
        r.register_credentials({'Authorization':secret})
        self.assertEqual(r.redact_text('prefix'+secret+'suffix'),'prefix'+secret+'suffix')
        self.assertEqual(r.redact_text('('+secret+')'),'([REDACTED])')
        source='{"value": true, "number": 123456789012, "missing": null}'
        r.register_credentials({'Cookie':'debug=true; absent=undefined; lang=en-US'})
        self.assertEqual(json.loads(r.redact_text(source)),json.loads(source))
    def test_top_level_json_literals_and_primitive_jsonl_stay_valid(self):
        r.register_credentials({'Authorization':'123456789012'})
        for source in ['123456789012','true','false','null','-1.2e+12']:
            self.assertEqual(r.redact_text(source),source)
        self.assertEqual(json.loads(r.redact_text('"123456789012"')),r.REDACTED)
        source='123456789012\n{"id_token":"synthetic","ok":true}\nnull'
        values=[json.loads(line) for line in r.redact_text(source).splitlines()]
        self.assertEqual(values,[123456789012,{'id_token':r.REDACTED,'ok':True},None])
        value='boundary-credential-2026';r.register_credentials({'Authorization':value})
        self.assertEqual(r.redact_text('λ'+value+'λ'),'λ'+value+'λ')

    def test_percent_encoded_names_duplicate_params_and_valid_urls(self):
        source='https://name:pwd@example.test/cb?X%2DAPI%2DKey=one&code=two&state=three&code=four#section'
        output=r.redact_text(source);parsed=urlsplit(output)
        self.assertEqual(parsed.hostname,'example.test');self.assertEqual(parsed.path,'/cb');self.assertEqual(parsed.fragment,'section')
        self.assertNotIn('[',output)
        self.assertEqual([value for _,value in parse_qsl(parsed.query)],['[REDACTED]']*4)
        self.assertIn('%5BREDACTED%5D@',output)
    def test_best_effort_eviction_does_not_disable_key_redaction(self):
        secret='old-fixture-credential-2026';r.register_credentials({'Authorization':secret})
        for n in range(r.MAX_SECRETS+1):r.register_credentials({'Authorization':f'new-fixture-credential-{n:04d}'})
        self.assertNotIn(secret,r._SECRETS)
        self.assertEqual(r.sanitize({'X-API-Key':secret}),{'X-API-Key':r.REDACTED})
    def test_mixed_case_bearer_late_in_body(self):
        source='x'*1000+' bEaReR fixture-credential-secret'
        self.assertNotIn('fixture-credential-secret',r.redact_text(source))
