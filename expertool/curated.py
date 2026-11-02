"""Pinned, data-only Nuclei HTTP template subset; no YAML parser or executable DSL."""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .execution import checked_url
from .redaction import sanitize

DENIED_TAGS={'dos','fuzz','fuzzing','bruteforce','brute-force','intrusive','headless','code','oast'}
SEVERITIES={'info','low','medium','high','critical'}


class TemplateDenied(ValueError):pass


def tags(value):
    if isinstance(value,str):value=value.split(',')
    if not isinstance(value,list) or not value or not all(isinstance(t,str) and re.fullmatch(r'[a-z0-9-]{1,50}',t.strip().lower()) for t in value):
        raise TemplateDenied('Template tags must be explicit simple identifiers')
    return {t.strip().lower() for t in value}


def load_manifest(path,policy,target,allowed_tags,allowed_severities,excluded_tags=()):
    path=Path(path).resolve()
    if path.stat().st_size>262144:raise TemplateDenied('Manifest too large')
    manifest=json.loads(path.read_text())
    if not isinstance(manifest,dict) or set(manifest)!={'templates'} or not isinstance(manifest['templates'],list) or not 1<=len(manifest['templates'])<=50:
        raise TemplateDenied('Manifest requires 1–50 pinned templates')
    loaded=[];ids=set()
    for item in manifest['templates']:
        if not isinstance(item,dict) or set(item)!={'path','sha256'} or not isinstance(item['path'],str) or not re.fullmatch(r'[a-f0-9]{64}',str(item['sha256'])):
            raise TemplateDenied('Every template requires a path and SHA256')
        filename=(path.parent/item['path']).resolve()
        if not filename.is_relative_to(path.parent) or filename.stat().st_size>262144:
            raise TemplateDenied('Template must be bounded and inside the manifest directory')
        raw=filename.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise TemplateDenied('Template pin mismatch')
        template=json.loads(raw)
        validate_template(template,policy,target,allowed_tags,allowed_severities,set(excluded_tags)|DENIED_TAGS)
        if template['id'] in ids:raise TemplateDenied('Duplicate template ID')
        ids.add(template['id'])
        loaded.append({'template':template,'sha256':item['sha256']})
    return loaded


def validate_template(template,policy,target,allowed_tags,allowed_severities,excluded_tags):
    if sanitize(template)!=template:raise TemplateDenied('Credential-like content is forbidden in executable templates')
    if not isinstance(template,dict) or set(template)!={'id','info','http'} or not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}',str(template.get('id',''))):
        raise TemplateDenied('Only explicit id/info/http templates are supported')
    info=template['info']
    if not isinstance(info,dict) or set(info)-{'name','author','severity','description','tags','reference'} or not all(isinstance(info.get(k),str) and info[k] for k in ('name','author','severity')):
        raise TemplateDenied('Invalid template info')
    template_tags=tags(info.get('tags'))
    if template_tags & excluded_tags or not template_tags & set(allowed_tags):raise TemplateDenied('Template tag is not permitted')
    if info['severity'] not in set(allowed_severities):raise TemplateDenied('Template severity is not permitted')
    requests=template['http']
    if not isinstance(requests,list) or not 1<=len(requests)<=5:raise TemplateDenied('Only 1–5 independent HTTP blocks are supported')
    for request in requests:
        if not isinstance(request,dict) or set(request)-{'method','path','matchers','matchers-condition','redirects','max-redirects'}:
            raise TemplateDenied('Unsupported request feature (raw, payloads, flows and code are forbidden)')
        if request.get('method') not in {'GET','HEAD'} or request.get('redirects',False) is not False or request.get('max-redirects',0)!=0:
            raise TemplateDenied('Only GET/HEAD without redirects are supported')
        if request.get('matchers-condition','or') not in {'and','or'}:raise TemplateDenied('Invalid matcher condition')
        paths=request.get('path')
        if not isinstance(paths,list) or not 1<=len(paths)<=5:raise TemplateDenied('Each HTTP block requires 1–5 paths')
        for value in paths:
            if not isinstance(value,str) or not value.startswith(('{{BaseURL}}','{{RootURL}}')):raise TemplateDenied('Paths must use the approved base origin')
            root=target.rstrip('/') if value.startswith('{{BaseURL}}') else f'{urlsplit(target).scheme}://{urlsplit(target).netloc}'
            suffix=value.split('}}',1)[1]
            if suffix and (not suffix.startswith('/') or suffix.startswith('//')):raise TemplateDenied('Invalid relative template path')
            if '{{' in suffix or '}}' in suffix or '?' in suffix or '#' in suffix or len(suffix)>2048:raise TemplateDenied('Dynamic/query template payloads are forbidden')
            checked_url(policy,root+suffix)
        matchers=request.get('matchers')
        if not isinstance(matchers,list) or not 1<=len(matchers)<=10:raise TemplateDenied('Explicit bounded matchers required')
        for matcher in matchers:
            if not isinstance(matcher,dict) or set(matcher)-{'type','part','words','status','condition','name','negative','case-insensitive'}:
                raise TemplateDenied('Unsupported matcher fields')
            for flag in ('negative','case-insensitive'):
                if flag in matcher and type(matcher[flag]) is not bool:raise TemplateDenied('Matcher flags must be boolean')
            if 'name' in matcher and (not isinstance(matcher['name'],str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}',matcher['name'])):
                raise TemplateDenied('Invalid matcher name')
            kind=matcher.get('type')
            if kind not in {'word','status'} or matcher.get('part','body') not in {'body','header','all'}:
                raise TemplateDenied('Only literal/status matchers are supported')
            values=matcher.get('words' if kind=='word' else 'status')
            if not isinstance(values,list) or not 1<=len(values)<=20:raise TemplateDenied('Invalid matcher values')
            if kind=='word' and any(not isinstance(v,str) or not v or len(v)>4096 or '{{' in v for v in values):raise TemplateDenied('Invalid literal matcher')
            if kind=='status' and any(type(v) is not int or not 100<=v<=599 for v in values):raise TemplateDenied('Invalid status matcher')
            if matcher.get('condition','or') not in {'and','or'}:raise TemplateDenied('Invalid matcher condition')
