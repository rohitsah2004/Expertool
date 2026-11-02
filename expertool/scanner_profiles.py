"""Fixed non-intrusive scanner commands. No caller-supplied arbitrary flags."""
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit

from .adapters import parse_output
from .curated import DENIED_TAGS, SEVERITIES, tags
from .redaction import sanitize

SCANNERS={'httpx','nuclei','whatweb','wpscan'}
DEFAULTS={'enabled':[],'timeout':60,'max_output_bytes':2097152,'nuclei':{},'wpscan_database':None,'block_untested_versions':False,'stale_after_days':30}


def scanner_settings(policy):
    raw=policy.get('scanners',{})
    if not isinstance(raw,dict) or set(raw)-set(DEFAULTS):raise ValueError('Invalid scanner configuration')
    config={**DEFAULTS,**raw}
    if not isinstance(config['enabled'],list) or any(t not in SCANNERS for t in config['enabled']):raise ValueError('Unknown scanner')
    for key,low,high in [('timeout',1,300),('max_output_bytes',1024,8388608)]:
        if type(config[key]) is not int or not low<=config[key]<=high:raise ValueError(f'Invalid scanner {key}')
    if type(config['block_untested_versions']) is not bool:raise ValueError('block_untested_versions must be boolean')
    if type(config['stale_after_days']) is not int or not 1<=config['stale_after_days']<=3650:raise ValueError('Invalid staleness threshold')
    nuclei=config['nuclei']
    if not isinstance(nuclei,dict) or set(nuclei)-{'manifest','allowed_tags','allowed_severities','excluded_tags'}:raise ValueError('Invalid Nuclei settings')
    nuclei={'manifest':None,'allowed_tags':['tech','exposure','misconfig','cve'],'allowed_severities':['info','low','medium','high','critical'],'excluded_tags':[],**nuclei}
    nuclei['allowed_tags']=sorted(tags(nuclei['allowed_tags']))
    nuclei['excluded_tags']=sorted(tags(nuclei['excluded_tags'])|DENIED_TAGS) if nuclei['excluded_tags'] else sorted(DENIED_TAGS)
    if not isinstance(nuclei['allowed_severities'],list) or not nuclei['allowed_severities'] or any(v not in SEVERITIES for v in nuclei['allowed_severities']):raise ValueError('Invalid severity allowlist')
    config['nuclei']=nuclei
    return config


def build_command(tool,target,directory,http_config,timeout,templates=()):
    output=Path(directory)/'result.json'
    seconds=str(max(1,math.ceil(timeout)));rate=str(max(1,math.floor(http_config['rate_per_second'])))
    headers={'User-Agent':http_config['user_agent'],**http_config['request_headers']}
    if tool=='httpx':
        args=['httpx','-u',target,'-json','-silent','-no-color','-disable-update-check','-no-fallback-scheme','-threads','1','-rate-limit',rate,
              '-timeout',seconds,'-retries','0','-status-code','-title','-tech-detect','-hash','sha256','-response-size-to-read',str(http_config['max_response_bytes'])]
        for key,value in headers.items():args+=['-H',key+': '+value]
    elif tool=='nuclei':
        args=['nuclei','-u',target,'-jsonl','-silent','-no-color','-disable-update-check','-no-stdin','-no-httpx','-no-interactsh','-proxy-internal',
              '-omit-raw','-omit-template','-concurrency','1','-bulk-size','1','-rate-limit',rate,'-timeout',seconds,'-retries','0',
              '-exclude-tags',','.join(sorted(DENIED_TAGS))]
        for item in templates:
            # JSON is valid YAML; a canonical snapshot prevents post-review file mutation.
            path=Path(directory)/(item['template']['id']+'.yaml')
            path.write_text(json.dumps(item['template']))
            args+=['-t',str(path)]
        for key,value in headers.items():args+=['-H',key+': '+value]
    elif tool=='whatweb':
        args=['whatweb','--aggression=1','--follow-redirect=never','--no-cookies','--max-threads=1','--open-timeout='+seconds,
              '--read-timeout='+seconds,'--log-json='+str(output),'--user-agent='+http_config['user_agent']]
        for key,value in http_config['request_headers'].items():args+=['--header',key+': '+value]
        args.append(target)
    elif tool=='wpscan':
        args=['wpscan','--url',target,'--format','json','--output',str(output),'--no-update','--no-banner','--detection-mode','passive',
              '--plugins-detection','passive','--max-threads','1','--throttle',str(max(100,math.ceil(1000/http_config['rate_per_second']))),
              '--max-scan-duration',seconds,'--ignore-main-redirect','--scope',urlsplit(target).hostname,'--user-agent',http_config['user_agent'],
              '--cache-dir',str(Path(directory)/'cache'),'--cookie-jar',str(Path(directory)/'cookie-jar')]
        if http_config['request_headers']:args+=['--headers','; '.join(k+': '+v for k,v in http_config['request_headers'].items())]
    else:raise ValueError('Unknown scanner')
    return args,output


def normalize_output(tool,content,target):
    if tool in {'httpx','nuclei'}:
        records=parse_output(content,tool)
        if tool=='httpx':
            # Retain hashes without storing response bodies or captures.
            rows=[json.loads(line) for line in content.splitlines() if line.strip()]
            for record,row in zip(records,rows):
                if isinstance(row.get('hash'),dict):record['metadata']['hash']=sanitize(row['hash'])
        return records
    from .orchestrator import parse_whatweb,parse_wpscan
    if tool=='whatweb':return [{'url':target,'metadata':{'fingerprints':parse_whatweb(content)}}]
    parsed=parse_wpscan(json.loads(content))
    if parsed['scan_aborted']:raise ValueError('WPScan reported aborted scan')
    findings=[]
    for advisory in parsed['advisories']:
        identity=json.dumps([advisory.get('component'),advisory.get('id') or advisory.get('title')],sort_keys=True)
        findings.append({'check_id':'wpscan.'+hashlib.sha256(identity.encode()).hexdigest()[:24],
            'title':'WPScan advisory: '+str(advisory.get('title','Unnamed advisory')),'severity':'info',
            'evidence':json.dumps({'reported_advisory':advisory,'note':'Candidate only: applicability, severity and exploit impact require human validation.'})})
    return [{'url':target,'findings':findings,'metadata':parsed}]
