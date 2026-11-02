"""Offline scanner provenance; version probes execute only under verified isolation."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time

REGISTRY=Path(__file__).resolve().parent.parent/'data'/'tested-versions.json'
FLAGS={'httpx':['-version'],'nuclei':['-version'],'whatweb':['--version'],'wpscan':['--no-update','--version']}
PATTERNS={'httpx':r'(?:Current Version:|httpx(?: version)?)\s*v?(\d+\.\d+\.\d+)',
          'nuclei':r'Nuclei Engine Version:\s*v?(\d+\.\d+\.\d+)',
          'whatweb':r'WhatWeb version\s+v?(\d+\.\d+\.\d+)',
          'wpscan':r'(?:Version\s+)?\b(\d+\.\d+\.\d+)\b'}

def file_hash(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda:source.read(1048576),b''):digest.update(chunk)
    return digest.hexdigest()

def identify(tool,binary):
    result={'name':tool,'absolute_path':str(Path(binary).resolve()) if binary else None,
            'version':None,'version_string':None,'sha256':None,'version_status':'not-probed'}
    if binary:
        try:result['sha256']=file_hash(binary)
        except OSError:result['version_status']='unavailable'
    else:result['version_status']='missing'
    return result

def probe(identity):
    from .isolation import run_guarded,IsolationUnavailable
    from .scanners import isolated_environment
    tool=identity['name'];binary=identity['absolute_path']
    if not binary or not identity['sha256']:return identity
    try:
        with tempfile.TemporaryDirectory(prefix='expertool-version-') as directory:
            env=isolated_environment(directory,{})
            # Version output may go to stderr. Combine only for bounded parsing;
            # no arbitrary output is retained in records.
            content=run_guarded([binary,*FLAGS[tool]],5,65536,directory,environment_overrides=env,include_stderr=True)
        match=re.search(PATTERNS[tool],re.sub(r'\x1b\[[0-9;]*m','',content),re.I)
        if match:
            identity.update(version=match.group(1),version_string=match.group(0)[:160],version_status='observed')
        else:identity['version_status']='unrecognized'
    except IsolationUnavailable:identity['version_status']='isolation-unavailable'
    except (OSError,ValueError):identity['version_status']='probe-failed'
    return identity

def verify_identity(identity,registry=None):
    registry=json.loads(REGISTRY.read_text()) if registry is None else registry
    versions=registry.get('tools',{}).get(identity['name'],[])
    tested=identity['version'] in versions and identity['version_status']=='observed'
    return {'tested':tested,'tested_versions':versions,'warning':None if tested else 'Untested or unavailable scanner version'}

def freshness(path,threshold_days=30,directory=False,clock=None):
    """mtime is an observed file date, not proof of upstream database currency."""
    clock=time.time() if clock is None else clock
    result={'date':None,'age_days':None,'threshold_days':threshold_days,'stale':None,
            'date_basis':'oldest copied database file mtime' if directory else 'manifest file mtime',
            'warning':'Date unavailable; current coverage is not established'}
    if not path:return result
    try:
        root=Path(path)
        if directory:
            stamps=[f.stat().st_mtime for f in root.iterdir() if f.is_file() and not f.is_symlink() and (f.suffix in {'.json','.txt'} or f.name in {'dynamic_finders.yml','LICENSE'})]
            if not stamps:return result
            stamp=min(stamps)
        else:stamp=root.stat().st_mtime
        age=(clock-stamp)/86400
        result.update(date=datetime.fromtimestamp(stamp,timezone.utc).isoformat(),age_days=round(max(0,age),3),stale=age>threshold_days)
        result['warning']='File date is in the future; currency unverified' if age<0 else ('Data exceeds staleness threshold; no findings does not establish current coverage' if result['stale'] else None)
    except (OSError,ValueError,OverflowError):pass
    return result
