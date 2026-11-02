"""Persistent anonymous HTTP schedules and a bounded passive-tool launcher."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

from .adapters import parse_output
from .execution import checked_url, scan, settings
from .scope import hostname, matches, validate_program, automation_allowed


def tool_status(verify=False):
    rows= [{'tool': name, 'executable': shutil.which(name), 'launch_supported': name!='nmap',
             'execution_status':'blocked-non-http-protocol' if name=='nmap' else 'requires-program-opt-in-and-verified-process-isolation',
             'saved_output_import': name in {'subfinder','httpx','nuclei'}}
            for name in ('subfinder','httpx','nuclei','nmap','curl','whatweb','wpscan','searchsploit')]
    if verify:
        from .tool_identity import FLAGS,identify,probe,verify_identity
        for row in rows:
            if row['tool'] in FLAGS:
                row['tool_identity']=probe(identify(row['tool'],row['executable']))
                row['verification']=verify_identity(row['tool_identity'])
    return rows


def discover(workspace, program, domain, timeout=60):
    policy = workspace.policy(program)
    modes = validate_program(policy)
    automation_allowed(policy,'subfinder')
    if 'passive' not in modes:
        raise ValueError('Passive discovery is not allowed by program policy')
    domain = hostname(domain)
    if not any(matches(domain, rule) or rule == '*.' + domain for rule in policy['include']) or any(matches(domain, rule) for rule in policy['exclude']):
        raise ValueError('Discovery root is outside program scope')
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise ValueError('Tool timeout must be 1–120 seconds')
    run_id = workspace.start_run(program, 'subfinder', {'domain': domain, 'timeout': timeout})
    binary=shutil.which('subfinder')
    if not binary:
        workspace.finish_run(run_id,'skipped',{'reason':'Executable not installed'})
        raise ValueError('Subfinder is not installed on PATH')
    from .isolation import guard_context,run_in_context,IsolationUnavailable
    try:
        with tempfile.TemporaryDirectory(prefix='expertool-subfinder-') as directory:
            with guard_context(workspace,program,'subfinder',run_id):
                content=run_in_context([binary,'-d',domain,'-silent','-oJ','-duc','-rl','1','-max-time','1'],timeout,2097152,directory)
            records=parse_output(content,'subfinder-json')
            accepted=[record for record in records if any(matches(record['url'][6:],r) for r in policy['include'])
                      and not any(matches(record['url'][6:],r) for r in policy['exclude'])]
            result=workspace.import_records(program,accepted,f'subfinder:{run_id}')
            result.update({'run_id':run_id,'out_of_scope_discoveries':len(records)-len(accepted)})
            workspace.finish_run(run_id,'completed',result)
            return result
    except BaseException as error:
        status='skipped' if isinstance(error,IsolationUnavailable) else ('cancelled' if isinstance(error,KeyboardInterrupt) else 'failed')
        workspace.finish_run(run_id,status,{'error':type(error).__name__})
        raise


def add_schedule(workspace, program, seeds, interval):
    policy = workspace.policy(program)
    config = settings(policy)
    if type(interval) is not int or not 60 <= interval <= 31536000:
        raise ValueError('Schedule interval must be 60 seconds to one year')
    if not seeds:
        raise ValueError('Schedule needs seed URLs')
    urls = [checked_url(policy, seed, config) for seed in seeds]
    if policy.get('orchestration',{}).get('enabled'):
        from .orchestrator import configuration
        configuration(policy)
        if len(urls)!=1:
            raise ValueError('Proactive schedules require one target')
    with workspace.db:
        cursor = workspace.db.execute('INSERT INTO schedules(program,seeds,interval_seconds,next_due) VALUES(?,?,?,?)',
                                       (program, json.dumps(urls), interval, time.time()))
    return {'schedule_id': cursor.lastrowid, 'status': 'enabled', 'next_run': 'due now; starts when worker runs'}


def schedules(workspace):
    result = [dict(row) for row in workspace.db.execute('SELECT * FROM schedules ORDER BY id')]
    for row in result:
        row['seeds'] = json.loads(row['seeds'])
    return result


def set_schedule(workspace, schedule_id, enabled):
    with workspace.db:
        cursor = workspace.db.execute('UPDATE schedules SET enabled=? WHERE id=?', (int(enabled), schedule_id))
        if not cursor.rowcount:
            raise ValueError('Unknown schedule')


def run_due(workspace):
    # Claim at most one job atomically. A lease permits recovery after worker failure.
    now = time.time()
    with workspace.db:
        workspace.db.execute('BEGIN IMMEDIATE')
        row = workspace.db.execute('SELECT * FROM schedules WHERE enabled=1 AND next_due<=? AND lease_until<=? ORDER BY next_due LIMIT 1', (now, now)).fetchone()
        if row is None:
            return None
        policy=workspace.policy(row['program'])
        lease=750
        if policy.get('orchestration',{}).get('enabled'):
            from .orchestrator import configuration
            lease=configuration(policy)['max_seconds']+60
        workspace.db.execute('UPDATE schedules SET lease_until=?,next_due=? WHERE id=?',
                             (now + lease, now + row['interval_seconds'], row['id']))
    status = 'failed'
    try:
        if workspace.policy(row['program']).get('orchestration',{}).get('enabled'):
            from .orchestrator import assess
            seeds=json.loads(row['seeds'])
            if len(seeds)!=1:
                raise ValueError('Proactive schedules require one target')
            result=assess(workspace,row['program'],seeds[0])
        else:
            result = scan(workspace, row['program'], json.loads(row['seeds']))
        status = result['status']
        return {'schedule_id': row['id'], **result}
    except (ValueError, OSError) as error:
        return {'schedule_id': row['id'], 'status': status, 'error': type(error).__name__}
    finally:
        with workspace.db:
            workspace.db.execute('UPDATE schedules SET lease_until=0,last_status=? WHERE id=?', (status, row['id']))


def worker(workspace, once=False, poll=5):
    if not 1 <= poll <= 60:
        raise ValueError('Worker poll must be 1–60 seconds')
    try:
        while True:
            result = run_due(workspace)
            if result:
                print(json.dumps(result), flush=True)
            if once:
                return
            if result is None:
                time.sleep(poll)
    except KeyboardInterrupt:
        return
