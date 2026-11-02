import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from expertool.curated import TemplateDenied,load_manifest
from expertool.template_import import parse_yaml,import_templates

YAML='''id: fixture-yaml
info:
  name: YAML fixture
  author: expertool
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{RootURL}}/marker"
    matchers:
      - type: word
        words: [EXPERTOOL_FIXTURE_MARKER]
'''

@unittest.skipUnless(importlib.util.find_spec('yaml'),'optional PyYAML not installed')
class TemplateImportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.policy=json.loads(Path('examples/scanner-lab-program.json').read_text())
        self.source=self.root/'source.yaml';self.source.write_text(YAML)
        self.url='http://127.0.0.1:8901/'
    def tearDown(self):self.temp.cleanup()
    def test_yaml_roundtrip_pinned_and_review_required(self):
        out=self.root/'out';result=import_templates([self.source],out,self.policy,self.url)
        self.assertEqual(result['status'],'requires-human-review')
        loaded=load_manifest(out/'manifest.json',self.policy,self.url,['tech'],['info'])
        self.assertEqual(loaded[0]['template'],parse_yaml(YAML.encode()))
        review=json.loads((out/'review.json').read_text())
        self.assertEqual(review['templates'][0]['source_sha256'],hashlib.sha256(YAML.encode()).hexdigest())
    def test_unsafe_yaml_syntax(self):
        for raw in ['a: 1\na: 2','a: &a [1]\nb: *a','a: !!python/object/apply:os.system [echo]','a: 1\n---\nb: 2','a: {<<: {b: 1}}','['*21+'0'+']'*21,'a: 2020-01-01','a: .nan','[']:
            with self.subTest(raw=raw),self.assertRaises(TemplateDenied):parse_yaml(raw.encode())
    def test_source_size_budget(self):
        with self.assertRaises(TemplateDenied):parse_yaml(b' '*262145)
    def test_unsupported_behavior_never_removed(self):
        base=parse_yaml(YAML.encode())
        for field,value in [('raw',['GET / HTTP/1.1']),('headers',{'X-Test':'1'}),('payloads',{'x':['a']}),('extractors',[{'type':'regex'}])]:
            template=copy.deepcopy(base);template['http'][0][field]=value
            self.source.write_text(json.dumps(template))
            with self.subTest(field=field),self.assertRaises(TemplateDenied):import_templates([self.source],self.root/'out',self.policy,self.url)
            self.assertFalse((self.root/'out').exists())
    def test_batch_is_atomic_and_duplicate_ids_rejected(self):
        bad=self.root/'bad.yaml';bad.write_text('invalid: true')
        for sources in [[self.source,bad],[self.source,self.source]]:
            with self.assertRaises(TemplateDenied):import_templates(sources,self.root/'out',self.policy,self.url)
            self.assertFalse((self.root/'out').exists())
    def test_scope_tags_and_severity_enforced(self):
        for change in ['scope','tags','severity','method']:
            policy=copy.deepcopy(self.policy);template=parse_yaml(YAML.encode())
            if change=='scope':template['http'][0]['path']=['{{RootURL}}/never-submit']
            if change=='tags':template['info']['tags']='intrusive,tech'
            if change=='severity':template['info']['severity']='critical'
            if change=='method':template['http'][0]['method']='POST'
            self.source.write_text(json.dumps(template))
            with self.subTest(change=change),self.assertRaises(ValueError):import_templates([self.source],self.root/'out',policy,self.url)
    def test_output_never_overwritten(self):
        out=self.root/'out';out.mkdir();(out/'keep').write_text('keep')
        with self.assertRaises(TemplateDenied):import_templates([self.source],out,self.policy,self.url)
        self.assertEqual((out/'keep').read_text(),'keep')
