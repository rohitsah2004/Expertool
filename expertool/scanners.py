"""Milestone 2 live adapters: every launch requires the guarded proxy and OS backend."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from urllib.parse import urlsplit

from .curated import load_manifest, TemplateDenied
from .egress import EgressGuard, PolicySource, EgressDenied, revision
from .execution import checked_url, settings
from .isolation import run_guarded, IsolationUnavailable
from .proxy import ProxyServer
from .redaction import sanitize
from .scanner_profiles import SCANNERS,scanner_settings,build_command,normalize_output


class ScannerBlocked(ValueError):pass


def find_executable(name):return shutil.which(name)


def isolated_environment(directory,config):
    home=Path(directory)/'home';home.mkdir()
    environment={'HOME':str(home),'XDG_CONFIG_HOME':str(home/'config'),'XDG_CACHE_HOME':str(home/'cache'),
                 'NUCLEI_CONFIG_DIR':str(home/'nuclei'),'NUCLEI_TEMPLATES_DIRECTORY':str(home/'templates')}
    for path in environment.values():Path(path).mkdir(parents=True,exist_ok=True)
    # Ruby installations may need their gem paths, never their user's scanner config.
    for key in ('GEM_HOME','GEM_PATH'):
        if os.environ.get(key):environment[key]=os.environ[key]
    database=config.get('wpscan_database')
    if database:
        source=Path(database).resolve()
        if not source.is_dir():raise ScannerBlocked('Configured offline WPScan database is unavailable')
        destination=home/'.cache'/'wpscan'/'db';destination.mkdir(parents=True)
        total=0
        for file in source.iterdir():
            if file.is_symlink() or not file.is_file() or (file.suffix not in {'.json','.txt'} and file.name not in {'dynamic_finders.yml','LICENSE','.last_update'}):continue
            total+=file.stat().st_size
            if total>52428800:raise ScannerBlocked('Offline WPScan data exceeds copy budget')
            shutil.copyfile(file,destination/file.name)
        # Current and legacy cache locations refer to the same private data copy.
        (home/'cache'/'wpscan').mkdir(parents=True,exist_ok=True)
        (home/'cache'/'wpscan'/'db').symlink_to(destination,target_is_directory=True)
    return environment


def launch(tool,binary,args,directory,output,proxy,config,timeout,http_config):
    environment=isolated_environment(directory,config)
    if tool=='whatweb':environment['EXPERTOOL_DNS_MAP']=json.dumps(config.get('_whatweb_dns',{}))
    descriptors=[]
    try:
        args=[binary,*args[1:]]
        if tool in {'httpx','nuclei'}:
            read,write=os.pipe();descriptors.append(read)
            # Pass explicit httpx config or a Nuclei proxy list through an in-memory
            # pipe: no credential in argv, on-disk config, database or evidence.
            try:
                proxy_url=proxy.endpoint.environment()['HTTPS_PROXY']
                payload=(json.dumps({'proxy':proxy_url}) if tool=='httpx' else proxy_url)+'\n'
                os.write(write,payload.encode())
            finally:os.close(write)
            args+=['-config' if tool=='httpx' else '-proxy',f'/dev/fd/{read}']
        if tool in {'whatweb','wpscan'}:
            binary=str(Path(binary).resolve())
            with Path(binary).open('rb') as script:
                first_line=script.readline(512).decode(errors='replace')
            if not first_line.startswith('#!') or 'ruby' not in first_line:
                raise ScannerBlocked('Ruby CLI script required; opaque shell/binary wrappers are not supported')
            interpreter=first_line[2:].strip().split()
            if len(interpreter)==1 and Path(interpreter[0]).is_absolute() and Path(interpreter[0]).name=='ruby':
                ruby=interpreter[0] if Path(interpreter[0]).is_file() else None
            elif interpreter==['/usr/bin/env','ruby']:
                ruby=find_executable('ruby')
            else:
                raise ScannerBlocked('Unsupported Ruby shebang; explicit ruby interpreter required')
            if not ruby:raise IsolationUnavailable('Ruby interpreter unavailable')
            environment['EXPERTOOL_SCANNER']=tool
            args=[ruby,str(Path(__file__).with_name('helpers')/'ruby_scanner.rb'),*args]
        return run_guarded(args,timeout,config['max_output_bytes'],directory,[output],endpoint=proxy.endpoint,
                           pass_fds=descriptors,environment_overrides=environment,accepted_exit_codes=(0,5) if tool=='wpscan' else (0,))
    finally:
        for descriptor in descriptors:os.close(descriptor)


def audit_counts(workspace,run_id):
    rows=workspace.db.execute('SELECT decision,count(*) AS n FROM egress_events WHERE run_id=? GROUP BY decision',(run_id,)).fetchall()
    return {row['decision']:row['n'] for row in rows}


def run_scanner(workspace,program,tool,target,time_budget=None):
    if tool not in SCANNERS:raise ValueError('Unsupported live scanner')
    run_id=workspace.start_run(program,tool,{'target':target,'mode':'guarded-anonymous'})
    from .tool_identity import identify,probe,verify_identity,freshness,file_hash
    binary=find_executable(tool)
    result={'run_id':run_id,'tool':tool,'status':'failed','tool_identity':identify(tool,binary),'warnings':[]}
    try:
        policy=workspace.policy(program)
        try:
            config=scanner_settings(policy)
            http_config=settings(policy,tool=tool)
            target=checked_url(policy,target,http_config)
        except ValueError as error:
            raise ScannerBlocked(str(error)) from error
        if tool not in config['enabled']:raise ScannerBlocked('Scanner is not enabled in this program')
        if tool=='wpscan':result['data_freshness']=freshness(config['wpscan_database'],config['stale_after_days'],directory=True)
        if tool=='nuclei':result['data_freshness']=freshness(config['nuclei']['manifest'],config['stale_after_days'])
        if result.get('data_freshness',{}).get('warning'):result['warnings'].append(result['data_freshness']['warning'])
        if not binary:
            result.update(status='skipped',reason='Executable not installed on PATH')
            return result
        templates=[]
        if tool=='nuclei':
            nuclei=config['nuclei']
            if not nuclei['manifest']:raise TemplateDenied('A reviewed pinned template manifest is required')
            templates=load_manifest(nuclei['manifest'],policy,target,nuclei['allowed_tags'],nuclei['allowed_severities'],nuclei['excluded_tags'])
        guard=EgressGuard(PolicySource(policy,workspace,program),tool,run_id)
        permit=guard.authorize(target,connect=urlsplit(target).scheme=='https',headers_supported=True)
        if tool=='whatweb':config={**config,'_whatweb_dns':{permit.host:permit.ips[0]}}
        timeout=min(config['timeout'],http_config['max_seconds'],time_budget if time_budget is not None else 300)
        if timeout<=0:raise ScannerBlocked('Pipeline time budget exhausted')
        result['tool_identity']=probe(result['tool_identity'])
        result['tool_verification']=verify_identity(result['tool_identity'])
        if not result['tool_verification']['tested']:
            result['warnings'].append(result['tool_verification']['warning'])
            if config['block_untested_versions']:raise ScannerBlocked('Program blocks untested scanner versions')
        if result['tool_identity']['sha256'] and file_hash(binary)!=result['tool_identity']['sha256']:
            raise ScannerBlocked('Scanner executable changed during version probe')
        with tempfile.TemporaryDirectory(prefix='expertool-'+tool+'-') as directory:
            args,output=build_command(tool,target,directory,http_config,timeout,templates)
            with ProxyServer(workspace,program,tool,run_id,headers_supported=True) as proxy:
                proxy.guard.expected_version=revision(policy)
                stdout=launch(tool,binary,args,directory,output,proxy,config,timeout,http_config)
            counts=audit_counts(workspace,run_id)
            if counts.get('allowed',0)==0:
                raise ScannerBlocked('No guarded target request observed; output is not trusted')
            content=output.read_text() if tool in {'whatweb','wpscan'} and output.exists() else stdout
            if tool in {'whatweb','wpscan'} and not output.exists():raise ValueError('Scanner output file missing')
            records=normalize_output(tool,content,target)
            allowed_ids={item['template']['id']:item for item in templates}
            current=workspace.policy(program);current_http=settings(current,tool=tool)
            if revision(current)!=revision(policy):raise ScannerBlocked('Policy changed during scanner run; review and restart')
            for record in records:
                try:checked_url(current,record['url'],current_http)
                except ValueError as error:raise ScannerBlocked('Scanner reported an asset outside current scope') from error
                record.setdefault('metadata',{}).update({'live_run_id':run_id,'tool':tool})
                if tool=='nuclei':
                    identifier=record['metadata'].get('template-id')
                    if identifier not in allowed_ids:raise ScannerBlocked('Output refers to a template outside the reviewed manifest')
                    item=allowed_ids[identifier]
                    if record['metadata'].get('reported_severity')!=item['template']['info']['severity']:
                        raise ScannerBlocked('Reported severity does not match the pinned template')
                    record['metadata']['template_sha256']=item['sha256']
                    for finding in record.get('findings',[]):
                        finding['evidence']=json.dumps({'template_id':identifier,'template_sha256':item['sha256'],
                            'matched_url':record['url'],'live_run_id':run_id,'note':'Scanner match only; human validation required.'})
            imported=workspace.import_records(program,records,f'{tool}:live:{run_id}')
            result.update(status='completed-with-blocks' if counts.get('denied') else 'completed',**imported,
                          allowed_requests=counts.get('allowed',0),denied_requests=counts.get('denied',0),
                          template_pins=[{'id':item['template']['id'],'sha256':item['sha256']} for item in templates])
            return result
    except (ScannerBlocked,TemplateDenied,EgressDenied) as error:
        result.update(status='blocked',reason=sanitize(str(error)))
        return result
    except IsolationUnavailable:
        result.update(status='skipped',reason='Verified process isolation or required runtime unavailable')
        return result
    except (ValueError,OSError,TypeError,KeyError) as error:
        counts=audit_counts(workspace,run_id)
        result.update(status='blocked' if counts.get('denied') else 'failed',
                      reason='Proxy denied scanner activity' if counts.get('denied') else type(error).__name__+'; scanner/output rejected; raw stderr omitted')
        return result
    except KeyboardInterrupt:
        result.update(status='cancelled',reason='Interrupted');raise
    finally:
        workspace.finish_run(run_id,result['status'],result)
