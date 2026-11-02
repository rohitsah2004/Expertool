"""Offline YAML admission: bounded syntax, no constructors, no silent feature removal."""
import hashlib
import json
from pathlib import Path
import tempfile
import os

from .curated import TemplateDenied, validate_template
from .scanner_profiles import scanner_settings
from .scope import validate_program
from .execution import settings, checked_url

LIMIT=262144


def parse_yaml(raw):
    if len(raw)>LIMIT:raise TemplateDenied('Template exceeds 256 KiB')
    try:
        import yaml
    except ImportError:
        raise TemplateDenied('YAML import requires optional PyYAML; see requirements-yaml.txt') from None
    try:
        # Events are consumed before construction. Reject aliases, anchors, explicit
        # tags, multiple documents and deep/node-heavy structures before allocation.
        depth=0;count=0;documents=0
        for event in yaml.parse(raw,Loader=yaml.SafeLoader):
            count+=1
            if count>10000:raise TemplateDenied('Too many YAML nodes')
            if isinstance(event,yaml.events.DocumentStartEvent):documents+=1
            if documents>1:raise TemplateDenied('Only one YAML document is accepted')
            if isinstance(event,yaml.events.AliasEvent) or getattr(event,'anchor',None) or getattr(event,'tag',None):
                raise TemplateDenied('YAML tags, anchors and aliases are forbidden')
            if isinstance(event,(yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent)):
                depth+=1
                if depth>20:raise TemplateDenied('YAML nesting limit exceeded')
            if isinstance(event,(yaml.events.MappingEndEvent,yaml.events.SequenceEndEvent)):depth-=1
        class Loader(yaml.SafeLoader):pass
        def mapping(loader,node):
            result={}
            for key_node,value_node in node.value:
                key=loader.construct_object(key_node,deep=True)
                if not isinstance(key,str) or key=='<<' or key in result:
                    raise TemplateDenied('Duplicate, merge or non-string YAML key')
                result[key]=loader.construct_object(value_node,deep=True)
            return result
        Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
        document=yaml.load(raw,Loader=Loader)
        # Dates, binary scalars and non-JSON values cannot cross admission.
        json.dumps(document,allow_nan=False)
        return document
    except TemplateDenied:raise
    except (yaml.YAMLError,UnicodeError,ValueError,TypeError,RecursionError):
        raise TemplateDenied('Invalid or unsupported YAML; source content omitted') from None


def import_templates(sources,destination,policy,target):
    validate_program(policy)
    config=scanner_settings(policy)['nuclei']
    target=checked_url(policy,target,settings(policy,tool='nuclei'))
    if not 1<=len(sources)<=50:raise TemplateDenied('Import requires 1–50 source files')
    admitted=[];ids=set()
    for source in sources:
        with Path(source).open('rb') as stream:raw=stream.read(LIMIT+1)
        template=parse_yaml(raw)
        # No execution fields are dropped or rewritten. Unsupported fields fail.
        validate_template(template,policy,target,config['allowed_tags'],config['allowed_severities'],set(config['excluded_tags']))
        if template['id'] in ids:raise TemplateDenied('Duplicate template ID')
        ids.add(template['id'])
        canonical=(json.dumps(template,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
        if len(canonical)>LIMIT:raise TemplateDenied('Canonical template exceeds size budget')
        admitted.append((template['id'],canonical,hashlib.sha256(raw).hexdigest()))
    destination=Path(destination)
    if destination.exists():raise TemplateDenied('Output directory already exists; refusing overwrite')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.template-import-',dir=destination.parent) as staging:
        stage=Path(staging)/'bundle';stage.mkdir(mode=0o700)
        manifest={'templates':[]};review=[]
        for identifier,canonical,source_hash in admitted:
            name=identifier+'.json';pin=hashlib.sha256(canonical).hexdigest()
            (stage/name).write_bytes(canonical)
            manifest['templates'].append({'path':name,'sha256':pin})
            review.append({'id':identifier,'source_sha256':source_hash,'canonical_sha256':pin})
        (stage/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        (stage/'review.json').write_text(json.dumps({'status':'requires-human-review','templates':review,
            'note':'Import does not enable scanning or establish vulnerability impact.'},indent=2)+'\n')
        # Publish only after every source has passed. Never merge partial batches.
        os.rename(stage,destination)
    return {'status':'requires-human-review','count':len(admitted),'manifest':str(destination/'manifest.json')}
