import argparse
import json
import os
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from .scope import hostname, matches, validate_program, plan

ROOT = Path(__file__).resolve().parent.parent


def load_catalog(path):
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError('Catalog must be a JSON array')
    seen = set()
    required = {'id', 'name', 'category', 'mode', 'prerequisites', 'evidence', 'sources'}
    for entry in entries:
        if not isinstance(entry, dict) or not required <= entry.keys():
            raise ValueError('Each technique needs id, name, category, mode, prerequisites, evidence, sources')
        for key in ('id', 'name', 'category'):
            if not isinstance(entry[key], str) or not entry[key].strip():
                raise ValueError(f'Invalid {key}')
        if entry['id'] in seen:
            raise ValueError(f'Duplicate technique: {entry["id"]}')
        seen.add(entry['id'])
        if entry['mode'] not in {'passive', 'active', 'manual'}:
            raise ValueError('mode must be passive, active or manual')
        for key in ('prerequisites', 'evidence', 'sources'):
            if not isinstance(entry[key], list) or not entry[key] or not all(isinstance(x, str) and x.strip() for x in entry[key]):
                raise ValueError(f'{key} must be a nonempty list of strings')
        if not all(urlsplit(url).scheme == 'https' and urlsplit(url).hostname for url in entry['sources']):
            raise ValueError('Sources must be HTTPS URLs')
    return entries



def main():
    parser = argparse.ArgumentParser(description='Expertool bug bounty assessment workspace')
    parser.add_argument('--catalog', default=str(ROOT / 'data/techniques.json'))
    parser.add_argument('--db', default='expertool.db', help='Local SQLite workspace')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('ca-create','ca-export-public','ca-destroy'):
        ca_parser=sub.add_parser(name,help='Explicit local interception CA lifecycle (no trust installation)')
        ca_parser.add_argument('--ca-dir',default=str(Path.home()/'.local/share/expertool/interception-ca'))
        if name=='ca-export-public':ca_parser.add_argument('--out',required=True)
    intercept=sub.add_parser('intercept-start',help='Start the separate opt-in manual interception listener')
    intercept.add_argument('--program',required=True)
    intercept.add_argument('--ca-dir',default=str(Path.home()/'.local/share/expertool/interception-ca'))
    intercept.add_argument('--port',type=int,default=0)
    intercept.add_argument('--token-env',default='EXPERTOOL_INTERCEPT_TOKEN')
    stop=sub.add_parser('intercept-stop',help='Stop a manual listener using its per-run proxy token')
    stop.add_argument('--port',type=int,required=True)
    stop.add_argument('--token-env',default='EXPERTOOL_INTERCEPT_TOKEN')
    search = sub.add_parser('catalog')
    search.add_argument('--search', default='')
    sub.add_parser('validate')
    planner = sub.add_parser('plan')
    planner.add_argument('--program', required=True)
    planner.add_argument('--target', required=True)
    program = sub.add_parser('program-add', help='Register an authorized program policy')
    program.add_argument('--name', required=True)
    program.add_argument('--file', required=True)
    update=sub.add_parser('program-update',help='Apply a reviewed policy update; guards reload it on each request')
    update.add_argument('--name',required=True)
    update.add_argument('--file',required=True)
    proxy=sub.add_parser('egress-proxy',help='Serve an authenticated loopback forward proxy')
    proxy.add_argument('--program',required=True)
    proxy.add_argument('--tool',default='http')
    proxy.add_argument('--port',type=int,default=8766)
    proxy.add_argument('--token-env',default='EXPERTOOL_PROXY_TOKEN')
    egress=sub.add_parser('egress-log',help='Read request admission records without headers or URL query strings')
    egress.add_argument('--program',required=True)
    scope_import=sub.add_parser('scope-import',help='Convert an offline scope export into a disabled review draft')
    scope_import.add_argument('--format',choices=['hackerone','normalized'],required=True)
    scope_import.add_argument('--file',required=True)
    scope_import.add_argument('--exclusions')
    scope_import.add_argument('--out',required=True)
    templates=sub.add_parser('template-import',help='Convert reviewed YAML into the pinned safe subset, offline')
    templates.add_argument('--program',required=True)
    templates.add_argument('--url',required=True)
    templates.add_argument('--file',action='append',required=True)
    templates.add_argument('--out',required=True)
    importer = sub.add_parser('import', help='Import normalized JSONL records or saved HTTP headers')
    importer.add_argument('--program', required=True)
    importer.add_argument('--file', required=True)
    from .adapters import FORMATS
    importer.add_argument('--format', choices=FORMATS, default='normalized')
    importer.add_argument('--source', help='Provenance label (defaults to selected format)')
    for command in ('show', 'report'):
        view = sub.add_parser(command)
        view.add_argument('--program', required=True)
    review = sub.add_parser('review')
    review.add_argument('--id', type=int, required=True)
    review.add_argument('--state', choices=['candidate', 'confirmed', 'dismissed'], required=True)
    dashboard = sub.add_parser('serve', help='Launch the local review dashboard')
    dashboard.add_argument('--port', type=int, default=8765)
    live = sub.add_parser('scan', help='Run a bounded scoped HTTP assessment')
    live.add_argument('--program', required=True)
    live.add_argument('--url', action='append', required=True)
    live.add_argument('--auth-profile')
    live.add_argument('--checks')
    live.add_argument('--no-crawl', action='store_true')
    live.add_argument('--compare-auth', action='store_true')
    live.add_argument('--proxy-url')
    live.add_argument('--proxy-token-env',default='EXPERTOOL_PROXY_TOKEN')
    proactive = sub.add_parser('assess', help='Automatically select relevant tools for an approved target')
    proactive.add_argument('--program', required=True)
    proactive.add_argument('--url', required=True)
    proactive.add_argument('--dry-run', action='store_true')
    scanner=sub.add_parser('scanner-run',help='Run an enabled live scanner through the verified egress boundary')
    scanner.add_argument('--program',required=True)
    scanner.add_argument('--tool',choices=['httpx','nuclei','whatweb','wpscan'],required=True)
    scanner.add_argument('--url',required=True)
    validation = sub.add_parser('recheck', help='Reproduce a supported finding condition without changing review state')
    validation.add_argument('--id', type=int, required=True)
    validation.add_argument('--auth-profile')
    validation.add_argument('--checks')
    access = sub.add_parser('access-check', help='Check an expected private canary boundary using two controlled accounts')
    access.add_argument('--program', required=True)
    access.add_argument('--url', required=True)
    access.add_argument('--owner-profile', required=True)
    access.add_argument('--other-profile', required=True)
    access.add_argument('--marker-env', required=True)
    access.add_argument('--expect-denied', action='store_true', required=True,
                        help='Declare that the other account must not be able to read this owned canary')
    tools_parser=sub.add_parser('tools', help='Inspect installed external tools')
    tools_parser.add_argument('--verify',action='store_true')
    audit_parser=sub.add_parser('audit-verify',help='Verify the global egress hash chain')
    audit_parser.add_argument('--checkpoint',help='Previously exported checkpoint JSON')
    audit_parser.add_argument('--out',help='Write current checkpoint to a new file')
    discovery = sub.add_parser('discover', help='Run installed Subfinder with bounded passive discovery')
    discovery.add_argument('--program', required=True)
    discovery.add_argument('--domain', required=True)
    discovery.add_argument('--timeout', type=int, default=60)
    schedule = sub.add_parser('schedule-add')
    schedule.add_argument('--program', required=True)
    schedule.add_argument('--url', action='append', required=True)
    schedule.add_argument('--interval', type=int, required=True, help='Seconds, minimum 60')
    sub.add_parser('schedules')
    toggle = sub.add_parser('schedule-set')
    toggle.add_argument('--id', type=int, required=True)
    toggle.add_argument('--enabled', choices=['yes', 'no'], required=True)
    worker = sub.add_parser('worker', help='Execute due scheduled assessments')
    worker.add_argument('--once', action='store_true', help='Execute at most one due schedule then exit')
    worker.add_argument('--poll', type=int, default=5)
    args = parser.parse_args()
    try:
        entries = load_catalog(args.catalog) if args.command in {'catalog', 'validate', 'plan'} else []
        if args.command in {'ca-create','ca-export-public','ca-destroy'}:
            from .local_ca import LocalCA
            ca=LocalCA(args.ca_dir)
            result=ca.create() if args.command=='ca-create' else (ca.export_public(args.out) if args.command=='ca-export-public' else ca.destroy())
            print(json.dumps(result,indent=2))
        elif args.command == 'intercept-stop':
            import base64,http.client
            token=os.environ.get(args.token_env)
            if not token or len(token)<24:raise ValueError('Set a strong per-run interception token in the named environment variable')
            if not 1<=args.port<=65535:raise ValueError('Invalid interception port')
            connection=http.client.HTTPConnection('127.0.0.1',args.port,timeout=3)
            try:
                auth='Basic '+base64.b64encode(('expertool:'+token).encode()).decode()
                connection.request('POST','/__expertool_stop',headers={'Proxy-Authorization':auth,'Content-Length':'0'})
                response=connection.getresponse();response.read(1024)
                if response.status!=200:raise ValueError('Listener refused stop; check port and per-run token')
            finally:connection.close()
            print(json.dumps({'stopped':True,'port':args.port}))
        elif args.command == 'scope-import':
            from .scope_import import convert_scope
            document=json.loads(Path(args.file).read_text())
            exclusions=json.loads(Path(args.exclusions).read_text()) if args.exclusions else None
            draft=convert_scope(document,args.format,exclusions)
            with Path(args.out).open('x') as output:
                output.write(json.dumps(draft,indent=2)+'\n')
            print(json.dumps({'draft':args.out,'authorized':False,'review_blockers':draft['scope_review']['blockers']},indent=2))
        elif args.command == 'serve':
            from .dashboard import serve
            if not 0 <= args.port <= 65535:
                raise ValueError('Port must be between 0 and 65535')
            serve(args.db, args.port)
        elif args.command == 'tools':
            from .jobs import tool_status
            print(json.dumps(tool_status(args.verify), indent=2))
        elif args.command == 'validate':
            print(f'Valid catalog: {len(entries)} techniques')
        elif args.command == 'catalog':
            query = args.search.casefold()
            print(json.dumps([e for e in entries if query in json.dumps(e).casefold()], indent=2))
        elif args.command == 'plan':
            print(json.dumps(plan(json.loads(Path(args.program).read_text()), args.target, entries), indent=2))
        else:
            from .workspace import Workspace, inspect_headers, markdown_report
            workspace = Workspace(args.db)
            try:
                if args.command == 'intercept-start':
                    from .intercept import InterceptServer
                    from .local_ca import LocalCA
                    token=os.environ.get(args.token_env)
                    if not token or len(token)<24:raise ValueError('Set a strong per-run interception token in the named environment variable')
                    run_id=workspace.start_run(args.program,'intercept',{'listener':'manual','port':args.port,'raw_capture':False})
                    status='failed';result={}
                    try:
                        with InterceptServer(workspace,args.program,run_id,LocalCA(args.ca_dir),args.port,token) as server:
                            print(json.dumps({'listener':'manual-interception','run_id':run_id,'proxy':'http://127.0.0.1:'+str(server.server_port),
                              'username':'expertool','password_environment':args.token_env,'http':'HTTP/1.1 only','raw_capture':False}),flush=True)
                            try:
                                while not server.stopping.wait(.25):pass
                            except KeyboardInterrupt:server.stop()
                            status='revoked' if server.revoked.is_set() else 'completed'
                            result={'raw_capture':False,'revoked':server.revoked.is_set()}
                    finally:workspace.finish_run(run_id,status,result)
                elif args.command == 'audit-verify':
                    anchor=json.loads(Path(args.checkpoint).read_text()) if args.checkpoint else None
                    result=workspace.verify_audit(anchor)
                    print(json.dumps(result,indent=2))
                    if not result['valid']:parser.exit(1)
                    if args.out:
                        with Path(args.out).open('x') as output:output.write(json.dumps(result['checkpoint'],indent=2)+'\n')
                elif args.command == 'program-update':
                    version=workspace.update_program(args.name,json.loads(Path(args.file).read_text()))
                    print(json.dumps({'program':args.name,'policy_version':version}))
                elif args.command == 'egress-log':
                    print(json.dumps(workspace.snapshot(args.program)['egress'],indent=2))
                elif args.command == 'egress-proxy':
                    from .proxy import ProxyServer
                    import time
                    token=os.environ.get(args.token_env)
                    if not token or len(token)<24:
                        raise ValueError('Set the proxy token environment variable to at least 24 random characters')
                    if not 0<=args.port<=65535:
                        raise ValueError('Invalid proxy port')
                    run_id=workspace.start_run(args.program,'egress-proxy',{'tool':args.tool,'port':args.port})
                    status='failed'
                    try:
                        with ProxyServer(workspace,args.program,args.tool,run_id,port=args.port,token=token) as server:
                            print('Egress proxy: '+server.endpoint.url+' (token remains in environment)',flush=True)
                            try:
                                while True:time.sleep(.5)
                            except KeyboardInterrupt:pass
                            status='completed'
                    finally:workspace.finish_run(run_id,status,{'reason':'proxy-stopped'})
                elif args.command == 'template-import':
                    from .template_import import import_templates
                    print(json.dumps(import_templates(args.file,args.out,workspace.policy(args.program),args.url),indent=2))
                elif args.command == 'scanner-run':
                    from .scanners import run_scanner
                    result=run_scanner(workspace,args.program,args.tool,args.url)
                    print(json.dumps(result,indent=2))
                    if result['status'] in {'failed','blocked'}:parser.exit(1)
                elif args.command == 'assess':
                    from .orchestrator import assess
                    print(json.dumps(assess(workspace,args.program,args.url,args.dry_run),indent=2))
                elif args.command == 'access-check':
                    from .execution import access_check, load_auth
                    print(json.dumps(access_check(workspace, args.program, args.url, load_auth(args.owner_profile),
                        load_auth(args.other_profile), os.environ.get(args.marker_env)), indent=2))
                elif args.command in {'scan', 'recheck'}:
                    from .execution import scan, validate_finding, load_auth, load_checks
                    auth, checks = load_auth(args.auth_profile), load_checks(args.checks)
                    proxy_endpoint=None
                    if args.command=='scan' and args.proxy_url:
                        from .proxy import ProxyEndpoint
                        address=urlsplit(args.proxy_url)
                        if address.scheme!='http' or address.username or address.password or address.path not in {'','/'} or address.query or address.fragment:
                            raise ValueError('Proxy URL must be a plain loopback HTTP authority')
                        proxy_endpoint=ProxyEndpoint(address.hostname,address.port,os.environ.get(args.proxy_token_env))
                    if args.command == 'scan' and workspace.policy(args.program).get('orchestration',{}).get('enabled'):
                        from .orchestrator import assess
                        if len(args.url)!=1:
                            raise ValueError('Proactive assessments accept one seed target per run')
                        if proxy_endpoint:
                            raise ValueError('Use a non-orchestrated program for an explicit built-in proxy session')
                        result=assess(workspace,args.program,args.url[0],auth=auth,checks=checks,crawl=not args.no_crawl,compare_auth=args.compare_auth)
                    else:
                        result = (scan(workspace, args.program, args.url, auth, checks, not args.no_crawl, args.compare_auth,proxy=proxy_endpoint)
                                  if args.command == 'scan' else validate_finding(workspace, args.id, auth, checks))
                    print(json.dumps(result, indent=2))
                    if result.get('status') == 'failed':
                        parser.exit(1)
                elif args.command == 'discover':
                    from .jobs import discover
                    print(json.dumps(discover(workspace, args.program, args.domain, args.timeout), indent=2))
                elif args.command == 'schedule-add':
                    from .jobs import add_schedule
                    print(json.dumps(add_schedule(workspace, args.program, args.url, args.interval), indent=2))
                elif args.command == 'schedules':
                    from .jobs import schedules
                    print(json.dumps(schedules(workspace), indent=2))
                elif args.command == 'schedule-set':
                    from .jobs import set_schedule
                    set_schedule(workspace, args.id, args.enabled == 'yes')
                    print('Schedule updated')
                elif args.command == 'worker':
                    from .jobs import worker
                    worker(workspace, args.once, args.poll)
                elif args.command == 'program-add':
                    workspace.add_program(args.name, json.loads(Path(args.file).read_text()))
                    print(f'Program registered: {args.name}')
                elif args.command == 'import':
                    from .adapters import parse_output
                    records = parse_output(Path(args.file).read_text(), args.format)
                    print(json.dumps(workspace.import_records(args.program, records, args.source or args.format), indent=2))
                elif args.command == 'review':
                    workspace.review(args.id, args.state)
                    print(f'Finding {args.id}: {args.state}')
                else:
                    snapshot = workspace.snapshot(args.program)
                    print(markdown_report(snapshot) if args.command == 'report' else json.dumps(snapshot, indent=2))
            finally:
                workspace.close()
    except (ValueError, OSError, TypeError, AttributeError, sqlite3.Error) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()
