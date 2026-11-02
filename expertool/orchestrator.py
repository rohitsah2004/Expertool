"""Target-driven tool selection. External tools are optional and policy-controlled."""
import ipaddress
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import threading
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from .execution import checked_url, Client, scan, settings
from .scope import automation_allowed, authorize_resolved_ips
from .isolation import IsolationUnavailable

TOOLS = ('nmap', 'curl', 'httpx', 'nuclei', 'whatweb', 'wpscan', 'searchsploit')
DEFAULT = {'enabled': False, 'tools': list(TOOLS), 'external_http': False,
           'timeout': 90, 'max_seconds': 300, 'max_output_bytes': 2097152,
           'nmap_tcp_ports': [80, 443], 'nmap_udp_ports': [], 'nmap_os': False,
           'network_authorized_ips': [], 'allow_wpscan_api': False}


def configuration(policy):
    raw = policy.get('orchestration', {})
    if not isinstance(raw, dict) or set(raw)-set(DEFAULT):
        raise ValueError('Unknown orchestration policy setting')
    config = {**DEFAULT, **raw}
    for key in ('enabled', 'external_http', 'nmap_os', 'allow_wpscan_api'):
        if type(config[key]) is not bool:
            raise ValueError(f'{key} must be boolean')
    if not isinstance(config['tools'], list) or any(t not in TOOLS for t in config['tools']):
        raise ValueError('Unknown orchestration tool')
    for key, low, high in [('timeout',1,300),('max_seconds',1,1800),('max_output_bytes',1024,8388608)]:
        if type(config[key]) is not int or not low <= config[key] <= high:
            raise ValueError(f'Invalid {key}')
    for key in ('nmap_tcp_ports', 'nmap_udp_ports'):
        value = config[key]
        if key == 'nmap_tcp_ports' and value == 'all':
            continue
        if not isinstance(value, list) or any(type(p) is not int or not 1<=p<=65535 for p in value):
            raise ValueError(f'{key} must be a TCP/UDP port array (TCP also accepts all)')
    if not isinstance(config['network_authorized_ips'], list):
        raise ValueError('network_authorized_ips must be a CIDR array')
    for cidr in config['network_authorized_ips']:
        ipaddress.ip_network(cidr)
    return config


def run_process(arguments, timeout, max_bytes, directory, watched=(), env=None):
    """Bound a trusted installed tool; no shell and no raw output in the database."""
    from .isolation import run_in_context
    return run_in_context(arguments,timeout,max_bytes,directory,watched)


def parse_nmap(content):
    if '<!ENTITY' in content.upper():
        raise ValueError('XML entities are not accepted')
    root = ET.fromstring(content)
    hosts = []
    for host in root.findall('host'):
        ports = []
        for port in host.findall('ports/port'):
            service, state = port.find('service'), port.find('state')
            entry = {'port': int(port.attrib['portid']), 'protocol': port.attrib.get('protocol'),
                     'state': state.attrib.get('state') if state is not None else 'unknown'}
            if service is not None:
                entry.update({key:service.attrib[key] for key in ('name','product','version','extrainfo','conf','method') if key in service.attrib})
                entry['cpe'] = [c.text for c in service.findall('cpe') if c.text]
            ports.append(entry)
        hosts.append({'addresses':[a.attrib.get('addr') for a in host.findall('address')], 'ports':ports,
                      'os_matches':[{'name':m.attrib.get('name'),'accuracy':m.attrib.get('accuracy')} for m in host.findall('os/osmatch')],
                      'status':host.find('status').attrib.get('state') if host.find('status') is not None else 'unknown'})
    return hosts


def parse_whatweb(content):
    # WhatWeb logs a JSON array, not the JSONL used by ProjectDiscovery tools.
    rows = json.loads(content)
    if not isinstance(rows,list):
        raise ValueError('WhatWeb JSON must be an array')
    result = []
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('plugins',{}),dict):
            raise ValueError('Malformed WhatWeb result')
        result.append({'http_status':row.get('http_status'), 'plugins':{
            name:{key:value for key,value in data.items() if key in {'version','string','certainty'}}
            for name,data in row.get('plugins',{}).items() if isinstance(data,dict)}})
    return result


def parse_wpscan(data):
    if not isinstance(data,dict):
        raise ValueError('WPScan JSON must be an object')
    components, advisories = [], []
    def component(kind, name, entry):
        if not isinstance(entry,dict):
            return
        version = entry.get('version')
        number = version.get('number') if isinstance(version,dict) else None
        components.append({'kind':kind, 'name':name, 'version':number})
        for advisory in entry.get('vulnerabilities',[]) or []:
            if not isinstance(advisory,dict):
                continue
            advisories.append({'component':name, 'installed_version':number,
                **{key:advisory[key] for key in ('id','title','fixed_in','references') if key in advisory}})
    component('core','WordPress',data.get('version'))
    # Core's version is itself a version object, unlike plugin version sub-objects.
    if components and isinstance(data.get('version'),dict):
        components[0]['version']=data['version'].get('number')
    for name, entry in (data.get('plugins') or {}).items():
        component('plugin',name,entry)
    theme=data.get('main_theme')
    if isinstance(theme,dict):
        component('theme',theme.get('slug','unknown-theme'),theme)
    api=data.get('vuln_api',{})
    return {'components':components, 'advisories':advisories,
            'api_data_reported': bool(isinstance(api,dict) and api.get('requests_done',0)),
            'scan_aborted':bool(data.get('scan_aborted'))}


def parse_searchsploit(data):
    if not isinstance(data,dict):
        raise ValueError('SearchSploit JSON must be an object')
    return [{key:item[key] for key in ('Title','EDB-ID','Date','Type','Platform') if key in item}
            for item in data.get('RESULTS_EXPLOIT',[])[:50] if isinstance(item,dict)]


def fingerprint(response):
    text=response.body.decode('utf-8',errors='replace')
    signals=[]
    for pattern, label in [(r'/wp-content/','wp-content resource'),(r'/wp-includes/','wp-includes resource'),
                            (r'(?i)name=[\"\']generator[\"\'][^>]+content=[\"\']WordPress','WordPress generator')]:
        if re.search(pattern,text):
            signals.append(label)
    match=re.search(r'(?i)WordPress\s+(\d+(?:\.\d+){1,3})',text)
    return {'wordpress':bool(signals), 'signals':signals, 'version_hint':match.group(1) if match and signals else None}


def resolve_destination(target, http_config, timeout, policy):
    """Allow network inventory even when the target's HTTP service is unavailable."""
    parsed=urlsplit(target)
    answers=[]
    errors=[]
    def resolve():
        try:
            answers.extend(socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme=='https' else 80),type=socket.SOCK_STREAM))
        except OSError as error:
            errors.append(error)
    thread=threading.Thread(target=resolve,daemon=True)
    thread.start();thread.join(max(.01,timeout))
    if thread.is_alive():raise TimeoutError('Target resolution timed out')
    if errors:raise errors[0]
    ips=sorted({a[4][0] for a in answers})
    authorize_resolved_ips(policy,ips)
    if not ips:raise ValueError('Target has no resolved addresses')
    for value in ips:
        ip=ipaddress.ip_address(value)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (not http_config['allow_private'] and not ip.is_global):
            raise ValueError('Destination is outside permitted address classes')
    return ips[0]


def assess(workspace, program, target, dry_run=False, auth=None, checks=None, crawl=True, compare_auth=False):
    policy=workspace.policy(program)
    http_config=settings(policy)
    target=checked_url(policy,target,http_config)
    config=configuration(policy)
    if not config['enabled']:
        raise ValueError('Set orchestration.enabled=true in this program to enable proactive assessments')
    plan={'target':target,'steps':['built-in-http',*config['tools']],
          'blocked_tools':{'whatweb':'No enforceable egress guard','wpscan':'No enforceable egress guard'},
          'conditional':{'wpscan':'only after WordPress fingerprint','searchsploit':'only detected product/version terms'},
          'limits':{'pipeline_seconds':config['max_seconds'],'per_tool_seconds':config['timeout']},
          'scan_profile':{'tcp_ports':config['nmap_tcp_ports'],'udp_ports':config['nmap_udp_ports'],'os_detection':config['nmap_os'],
                          'external_http':config['external_http']},
          'network_permission':'Nmap requires explicit network_authorized_ips, independent of hostname scope',
          'external_http_permission':'WhatWeb/WPScan require external_http=true and full-origin path scope'}
    if dry_run:
        return plan
    started=time.monotonic()
    run_id=workspace.start_run(program,'proactive',plan)
    steps=[]
    def remaining():
        return max(0,config['max_seconds']-(time.monotonic()-started))
    def step(name,status,**details):
        steps.append({'tool':name,'status':status,**details})
    try:
        # Inventory uses the existing engine; all imported findings remain candidates.
        base=scan(workspace,program,[target],auth,checks,crawl,compare_auth,time_budget=remaining())
        step('built-in-http',base['status'],run_id=base['run_id'])
        if remaining()<=0:
            result={'run_id':run_id,'target':target,'steps':steps,'status':'budget-limited'}
            workspace.finish_run(run_id,'budget-limited',result)
            return result
        client=Client(policy,auth,workspace=workspace,program=program,run_id=run_id)
        client.config['max_seconds']=min(client.config['max_seconds'],remaining())
        try:
            response=client.get(target)
            detected=fingerprint(response)
            ip=response.ip
        except (OSError,ValueError,http.client.HTTPException):
            detected={'wordpress':False,'signals':[],'version_hint':None,'http_fingerprint':'unavailable'}
            ip=resolve_destination(target,http_config,min(http_config['timeout'],remaining()),policy)
        workspace.import_records(program,[{'url':target,'metadata':{'pipeline_id':run_id,'fingerprint':detected}}],f'proactive:{run_id}')
        queries=[]
        if detected['wordpress']:
            queries.append('WordPress'+(' '+detected['version_hint'] if detected['version_hint'] else ''))
        env={k:v for k,v in os.environ.items() if k not in {'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'}}
        for tool in config['tools']:
            try:
                automation_allowed(policy,tool)
            except ValueError:
                step(tool,'blocked',reason='Program automation policy does not permit this tool');continue
            if tool in {'httpx','nuclei','whatweb','wpscan'}:
                from .scanners import run_scanner
                if auth:
                    step(tool,'blocked',reason='Live scanners are anonymous; account credentials are never forwarded');continue
                if tool=='wpscan' and not detected['wordpress']:
                    step(tool,'skipped',reason='No WordPress fingerprint');continue
                result=run_scanner(workspace,program,tool,target,time_budget=remaining())
                step(tool,result['status'],run_id=result['run_id'],summary=result)
                if result['status'].startswith('completed') and tool in {'whatweb','httpx'}:
                    for observation in workspace.snapshot(program)['observations']:
                        if observation['metadata'].get('live_run_id')==result['run_id'] and 'wordpress' in json.dumps(observation['metadata']).lower():
                            detected['wordpress']=True;queries.append('WordPress')
                if result['status'].startswith('completed') and tool=='wpscan':
                    for observation in workspace.snapshot(program)['observations']:
                        if observation['metadata'].get('live_run_id')==result['run_id']:
                            queries.extend(str(c['name'])+' '+str(c.get('version') or '') for c in observation['metadata'].get('components',[]))
                continue
            if remaining()<=0:
                step(tool,'skipped',reason='Pipeline time budget exhausted');continue
            if not shutil.which(tool):
                step(tool,'skipped',reason='Executable not installed on PATH');continue
            if tool=='wpscan' and not detected['wordpress']:
                step(tool,'skipped',reason='No WordPress fingerprint');continue
            if tool=='searchsploit' and not queries:
                step(tool,'skipped',reason='No product terms detected');continue
            with tempfile.TemporaryDirectory(prefix='expertool-assess-') as directory:
                try:
                    timeout=min(config['timeout'],remaining())
                    output=Path(directory)/'result.json'
                    metadata={}
                    reported_findings=[]
                    def execute(arguments,timeout,max_bytes,directory,watched=(),env=None):
                        from .isolation import guard_context
                        with guard_context(workspace,program,tool,run_id):
                            return run_process(arguments,timeout,max_bytes,directory,watched,env)
                    if tool=='nmap':
                        if http_config['request_headers']:
                            step(tool,'blocked',reason='Nmap service probes cannot enforce required HTTP identification headers');continue
                        if not any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for cidr in config['network_authorized_ips']):
                            step(tool,'skipped',reason='Resolved IP is not explicitly authorized for network scanning');continue
                        if http_config['path_prefixes']!=['/'] or http_config['excluded_paths']:
                            step(tool,'skipped',reason='Path-restricted web scope does not authorize host-level network assessment');continue
                        ports=config['nmap_tcp_ports']
                        if not ports:
                            step(tool,'skipped',reason='No TCP ports configured');continue
                        args=['nmap','-sT','-sV','--version-light','-Pn','-n','--max-retries','1','--max-rate',str(min(10,http_config['rate_per_second'])),
                              '--host-timeout',str(max(1,int(timeout)))+'s','-p','1-65535' if ports=='all' else ','.join(map(str,ports)), '-oX',str(output),ip]
                        if ipaddress.ip_address(ip).version==6:
                            args.insert(1,'-6')
                        if config['nmap_os']:
                            if hasattr(os,'geteuid') and os.geteuid()==0:
                                args.insert(1,'-O')
                            else:
                                metadata['os_detection']='skipped; requires existing raw-packet privileges; sudo is never invoked'
                        execute(args,timeout,config['max_output_bytes'],directory,[output],env)
                        inventory=parse_nmap(output.read_text())
                        metadata['tcp_inventory']=inventory
                        for host in inventory:
                            for port in host['ports']:
                                if port.get('product') and port['state']=='open':
                                    queries.append(str(port['product'])+' '+str(port.get('version','')))
                        if config['nmap_udp_ports']:
                            if hasattr(os,'geteuid') and os.geteuid()==0 and remaining()>0:
                                udp=Path(directory)/'udp.xml'
                                udp_args=['nmap','-sU','-sV','--version-light','-Pn','-n','--max-retries','1','--max-rate','1','--host-timeout',str(max(1,int(min(timeout,remaining()))))+'s','-p',','.join(map(str,config['nmap_udp_ports'])),'-oX',str(udp),ip]
                                if ipaddress.ip_address(ip).version==6:
                                    udp_args.insert(1,'-6')
                                execute(udp_args,min(timeout,remaining()),config['max_output_bytes'],directory,[udp],env)
                                metadata['udp_inventory']=parse_nmap(udp.read_text())
                            else:
                                metadata['udp_detection']='skipped; requires existing raw-packet privileges and remaining time'
                    elif tool=='curl':
                        parsed=urlsplit(target);port=parsed.port or (443 if parsed.scheme=='https' else 80)
                        headers=Path(directory)/'headers.txt';body=Path(directory)/'body.txt'
                        args=['curl','-q','--silent','--show-error','--noproxy','*','--proto','=http,https','--max-time',str(timeout),
                            '--connect-timeout',str(min(10,timeout)),'--max-filesize',str(http_config['max_response_bytes']),
                            '--resolve',f'{parsed.hostname}:{port}:{ip}','--output',str(body),'--dump-header',str(headers),'--write-out','%{http_code}',target]
                        args[1:1]=['--user-agent',http_config['user_agent']]
                        # -q must remain curl's first option to disable curlrc.
                        args.remove('-q');args.insert(1,'-q')
                        for key,value in http_config['request_headers'].items():
                            args[2:2]=['--header',key+': '+value]
                        status=execute(args,timeout,config['max_output_bytes'],directory,[body,headers],env)
                        metadata={'status_code':int(status.strip()),'redirects_followed':False,'body_persisted':False}
                    elif tool=='searchsploit':
                        references=[]
                        for query in list(dict.fromkeys(queries))[:5]:
                            if remaining()<=0:break
                            # Treat banners as data; do not let product names become command-line options.
                            terms=re.findall(r'[A-Za-z0-9][A-Za-z0-9_.+]*',query)[:8]
                            if not terms:continue
                            content=execute(['searchsploit','--json','--disable-colour',*terms],min(timeout,remaining()),config['max_output_bytes'],directory,env=env)
                            references.append({'query':' '.join(terms),'matches':parse_searchsploit(json.loads(content)),
                                               'classification':'research leads, not confirmed vulnerabilities'})
                        metadata={'references':references,'exploit_execution':False}
                    workspace.import_records(program,[{'url':target,'findings':reported_findings,'metadata':{'pipeline_id':run_id,'tool':tool,**metadata}}],f'proactive:{run_id}:{tool}')
                    step(tool,'completed',summary=metadata)
                except IsolationUnavailable:
                    step(tool,'skipped',reason='Process/egress isolation unavailable for this tool')
                except (ValueError,OSError,ET.ParseError,TypeError,KeyError) as error:
                    step(tool,'failed',reason=type(error).__name__)
        result={'run_id':run_id,'target':target,'fingerprint':detected,'steps':steps,
                'status':'completed-with-gaps' if any(s['status'] in {'failed','unavailable','budget-limited','skipped','blocked','completed-with-blocks','completed-with-gaps','cancelled'} for s in steps) else 'completed'}
        workspace.finish_run(run_id,result['status'],result)
        return result
    except BaseException as error:
        workspace.finish_run(run_id,'cancelled' if isinstance(error,KeyboardInterrupt) else 'failed',{'steps':steps,'error':type(error).__name__})
        raise
