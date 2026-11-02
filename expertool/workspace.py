"""Local storage and offline assessment imports. Nothing in this module sends requests."""
import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from .redaction import sanitize


def now():
    return datetime.now(timezone.utc).isoformat()


def normalize_url(value, allow_dns=False):
    from .scope import hostname
    if not isinstance(value, str):
        raise ValueError('Asset URL must be a string')
    parsed = urlsplit(value if '://' in value else 'https://' + value)
    schemes = {'https', 'http', 'dns'} if allow_dns else {'https', 'http'}
    if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Expected HTTP(S) URL without credentials')
    host = hostname(parsed.hostname)
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('URL port must be between 1 and 65535')
    if parsed.scheme == 'dns':
        if port is not None or parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
            raise ValueError('DNS assets must contain only a hostname')
        return 'dns://' + host, host
    authority = f'[{host}]' if ':' in host else host
    if port and port != (443 if parsed.scheme == 'https' else 80):
        authority += f':{port}'
    return urlunsplit((parsed.scheme, authority, parsed.path or '/', parsed.query, '')), host


class Workspace:
    def __init__(self, path):
        self.path = ('file:expertool-'+uuid.uuid4().hex+'?mode=memory&cache=shared') if str(path)==':memory:' else str(path)
        self.uri = self.path.startswith('file:expertool-')
        self.db = sqlite3.connect(self.path,uri=self.uri)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS programs (
          name TEXT PRIMARY KEY, policy TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS assets (
          id INTEGER PRIMARY KEY, program TEXT NOT NULL REFERENCES programs(name),
          url TEXT NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, created TEXT NOT NULL,
          UNIQUE(program,url));
        CREATE TABLE IF NOT EXISTS findings (
          id INTEGER PRIMARY KEY, asset INTEGER NOT NULL REFERENCES assets(id),
          check_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'candidate', evidence TEXT NOT NULL,
          fingerprint TEXT NOT NULL UNIQUE, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS observations (
          id INTEGER PRIMARY KEY, asset INTEGER NOT NULL REFERENCES assets(id),
          source TEXT NOT NULL, metadata TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
          created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs (
          id INTEGER PRIMARY KEY, program TEXT NOT NULL REFERENCES programs(name),
          kind TEXT NOT NULL, status TEXT NOT NULL, config TEXT NOT NULL,
          result TEXT NOT NULL DEFAULT '{}', started TEXT NOT NULL, finished TEXT);
        CREATE TABLE IF NOT EXISTS validations (
          id INTEGER PRIMARY KEY, finding INTEGER NOT NULL REFERENCES findings(id),
          verdict TEXT NOT NULL, evidence TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS schedules (
          id INTEGER PRIMARY KEY, program TEXT NOT NULL REFERENCES programs(name),
          seeds TEXT NOT NULL, interval_seconds INTEGER NOT NULL,
          next_due REAL NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          last_status TEXT, lease_until REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS egress_events (
          id INTEGER PRIMARY KEY, program TEXT NOT NULL, host TEXT, port INTEGER,
          decision TEXT NOT NULL, reason TEXT NOT NULL, tool TEXT NOT NULL,
          run_id INTEGER, policy_version TEXT, resolved_ip TEXT, transport TEXT,
          created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS policy_revisions (
          program TEXT NOT NULL, version TEXT NOT NULL, created TEXT NOT NULL,
          PRIMARY KEY(program,version));
        ''')
        from .audit import migrate
        migrate(self.db)

    def close(self):
        self.db.close()

    @contextmanager
    def reader(self):
        connection=sqlite3.connect(self.path,uri=self.uri,timeout=5)
        connection.row_factory=sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def audit_egress(self,program,host,port,decision,reason,tool,run_id,version,ip,transport,method=None,path_hash=None,injected_headers=(),source=None):
        values=sanitize([program,host,port,decision,reason,tool,run_id,version,ip,transport,now()])
        from .audit import append
        with self.reader() as connection:
            append(connection,values,sanitize({"method":method,"path_hash":path_hash,"injected_headers":list(injected_headers),"source":source}))

    def verify_audit(self,checkpoint=None):
        from .audit import verify
        with self.reader() as connection:
            return verify(connection,checkpoint)

    def update_program(self,name,policy):
        from .scope import validate_program
        from .egress import revision
        validate_program(policy)
        policy=sanitize(policy)
        deadline=time.monotonic()+2
        while True:
            try:
                with self.db:
                    cursor=self.db.execute('UPDATE programs SET policy=? WHERE name=?',(json.dumps(policy),name))
                    if not cursor.rowcount:raise ValueError('Unknown program')
                    self.db.execute('INSERT OR IGNORE INTO policy_revisions VALUES(?,?,?)',(name,revision(policy),now()))
                return revision(policy)
            except sqlite3.OperationalError as error:
                # Shared-cache in-memory readers return SQLITE_LOCKED without
                # honoring busy_timeout. Retry only this atomic local policy write.
                code=getattr(error,'sqlite_errorcode',0)&255
                if code not in {sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED} or time.monotonic()>=deadline:raise
                time.sleep(.005)

    def add_program(self, name, policy):
        from .scope import validate_program
        validate_program(policy)
        if not isinstance(name, str) or not name.strip():
            raise ValueError('Program name is required')
        with self.db:
            self.db.execute('INSERT INTO programs VALUES(?,?,?)', (name, json.dumps(sanitize(policy)), now()))

    def policy(self, name):
        row = self.db.execute('SELECT policy FROM programs WHERE name=?', (name,)).fetchone()
        if row is None:
            raise ValueError(f'Unknown program: {name}')
        return json.loads(row['policy'])

    def import_records(self, name, records, source):
        from .scope import plan, authorize_asset_url
        policy = self.policy(name)
        count = {'assets_added': 0, 'findings_added': 0, 'observations_added': 0, 'records': len(records)}
        # Validate the entire batch before committing any data.
        prepared = []
        for index, record in enumerate(records, 1):
            try:
                if not isinstance(record, dict):
                    raise ValueError('Record must be an object')
                url, host = normalize_url(record.get('url'), allow_dns=True)
                plan(policy, host, [])
                if not url.startswith('dns://'):
                    authorize_asset_url(policy,url)
                record=sanitize(record)
                url=sanitize(url)
                metadata = record.get('metadata', {})
                if not isinstance(metadata, dict):
                    raise ValueError('metadata must be an object')
                metadata_json = json.dumps(metadata, sort_keys=True, allow_nan=False)
                findings = record.get('findings', [])
                if not isinstance(findings, list):
                    raise ValueError('findings must be an array')
                for finding in findings:
                    if not isinstance(finding, dict):
                        raise ValueError('Finding must be an object')
                    for key in ('check_id', 'title', 'evidence'):
                        if not isinstance(finding.get(key), str) or not finding[key].strip():
                            raise ValueError(f'Finding requires nonempty {key}')
                    if finding.get('severity') not in {'info', 'low', 'medium', 'high', 'critical'}:
                        raise ValueError('Invalid severity')
                if url.startswith('dns://') and findings:
                    raise ValueError('DNS discovery assets cannot contain HTTP findings')
                prepared.append((url, host, findings, metadata_json))
            except (ValueError, TypeError, AttributeError) as error:
                raise ValueError(f'Record {index}: {error}') from error
        with self.db:
            for url, host, findings, metadata_json in prepared:
                cursor = self.db.execute('INSERT OR IGNORE INTO assets(program,url,host,source,created) VALUES(?,?,?,?,?)',
                                         (name, url, host, source, now()))
                count['assets_added'] += cursor.rowcount
                asset = self.db.execute('SELECT id FROM assets WHERE program=? AND url=?', (name, url)).fetchone()['id']
                fingerprint = hashlib.sha256(json.dumps([name, url, source, metadata_json]).encode()).hexdigest()
                cursor = self.db.execute('''INSERT OR IGNORE INTO observations
                    (asset,source,metadata,fingerprint,created) VALUES(?,?,?,?,?)''',
                    (asset, source, metadata_json, fingerprint, now()))
                count['observations_added'] += cursor.rowcount
                for finding in findings:
                    fingerprint = hashlib.sha256(json.dumps([name, url, finding['check_id']], separators=(',', ':')).encode()).hexdigest()
                    cursor = self.db.execute('''INSERT OR IGNORE INTO findings
                        (asset,check_id,title,severity,evidence,fingerprint,created) VALUES(?,?,?,?,?,?,?)''',
                        (asset, finding['check_id'], finding['title'], finding['severity'], finding['evidence'], fingerprint, now()))
                    count['findings_added'] += cursor.rowcount
        return count

    def review(self, finding_id, state):
        if state not in {'candidate', 'confirmed', 'dismissed'}:
            raise ValueError('Invalid review state')
        with self.db:
            cursor = self.db.execute('UPDATE findings SET state=? WHERE id=?', (state, finding_id))
            if not cursor.rowcount:
                raise ValueError(f'Unknown finding: {finding_id}')

    def start_run(self, program, kind, config):
        self.policy(program)
        with self.db:
            cursor = self.db.execute('INSERT INTO runs(program,kind,status,config,started) VALUES(?,?,?,?,?)',
                                     (program, kind, 'running', json.dumps(sanitize(config)), now()))
            return cursor.lastrowid

    def finish_run(self, run_id, status, result):
        with self.db:
            self.db.execute('UPDATE runs SET status=?,result=?,finished=? WHERE id=?', (status, json.dumps(sanitize(result)), now(), run_id))

    def record_validation(self, finding, verdict, evidence):
        with self.db:
            self.db.execute('INSERT INTO validations(finding,verdict,evidence,created) VALUES(?,?,?,?)',
                            (finding, verdict, json.dumps(sanitize(evidence)), now()))

    def snapshot(self, name):
        policy = self.policy(name)
        assets = [dict(r) for r in self.db.execute('SELECT * FROM assets WHERE program=? ORDER BY url', (name,))]
        findings = [dict(r) for r in self.db.execute('''SELECT f.*,a.url FROM findings f
            JOIN assets a ON a.id=f.asset WHERE a.program=? ORDER BY f.id''', (name,))]
        observations = [dict(r) for r in self.db.execute('''SELECT o.*,a.url FROM observations o
            JOIN assets a ON a.id=o.asset WHERE a.program=? ORDER BY o.id''', (name,))]
        for observation in observations:
            observation['metadata'] = json.loads(observation['metadata'])
        runs = [dict(r) for r in self.db.execute('SELECT * FROM runs WHERE program=? ORDER BY id DESC', (name,))]
        for run in runs:
            run['config'], run['result'] = json.loads(run['config']), json.loads(run['result'])
        validations = [dict(r) for r in self.db.execute('''SELECT v.* FROM validations v JOIN findings f ON f.id=v.finding
            JOIN assets a ON a.id=f.asset WHERE a.program=? ORDER BY v.id DESC''', (name,))]
        for validation in validations:
            validation['evidence'] = json.loads(validation['evidence'])
        schedules = [dict(r) for r in self.db.execute('SELECT * FROM schedules WHERE program=? ORDER BY id', (name,))]
        for schedule in schedules:
            schedule['seeds'] = json.loads(schedule['seeds'])
        egress=[dict(r) for r in self.db.execute('SELECT * FROM egress_events WHERE program=? ORDER BY id DESC LIMIT 1000',(name,))]
        return sanitize({'program': name, 'policy': policy, 'assets': assets, 'findings': findings, 'observations': observations,
                'runs': runs, 'validations': validations, 'schedules': schedules, 'egress':egress})


def inspect_headers(records):
    """Conservative posture observations from user-supplied captures, not vulnerability proof."""
    result = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict) or not isinstance(record.get('headers'), dict):
            raise ValueError(f'Record {index}: requires headers object')
        url, _ = normalize_url(record.get('url'))
        headers = {}
        for key, value in record['headers'].items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError('Header names and values must be strings')
            if key.lower() in headers:
                raise ValueError('Duplicate header names are ambiguous')
            headers[key.lower()] = value
        findings = []
        checks = [('x-content-type-options', 'Response lacks nosniff protection', 'nosniff')]
        if urlsplit(url).scheme == 'https':
            checks.append(('strict-transport-security', 'HTTPS response lacks HSTS policy', None))
        for header, title, expected in checks:
            if not headers.get(header) or (expected and headers[header].lower().strip() != expected):
                findings.append({'check_id': 'headers.' + header, 'title': title, 'severity': 'info',
                                 'evidence': f'Supplied capture did not contain the expected {header} policy. This is a configuration observation; exploitability and program eligibility are unverified.'})
        # Do not persist raw captures: they can contain cookies and credentials.
        result.append({'url': url, 'findings': findings})
    return result


def markdown_report(snapshot):
    lines = [f'# Assessment: {snapshot["program"]}', '',
             'Workspace evidence. Candidate findings require hunter validation.', '',
             f'Assets: {len(snapshot["assets"])} | Findings: {len(snapshot["findings"])}', '']
    for finding in snapshot['findings']:
        lines.extend([f'## Finding {finding["id"]}: {finding["title"]}', '',
                      f'Severity: {finding["severity"]} | State: {finding["state"]}', '',
                      f'Asset: {finding["url"]}', '', 'Evidence:', '',
                      *['    ' + line for line in finding['evidence'].splitlines()], ''])
        for validation in snapshot.get('validations', []):
            if validation['finding'] == finding['id']:
                lines.extend([f'Recheck: {validation["verdict"]} at {validation["created"]}', ''])
    if snapshot.get('runs'):
        lines.extend(['## Assessment runs', ''])
        for run in snapshot['runs']:
            lines.extend([f'Run {run["id"]}: {run["kind"]} — {run["status"]} — {run["started"]}', ''])
            identity=run.get('result',{}).get('tool_identity')
            if identity:lines.extend([f'Tool: {identity["name"]} | path: {identity["absolute_path"]} | version: {identity["version"] or "unavailable"} | SHA256: {identity["sha256"] or "unavailable"}', ''])
            data=run.get('result',{}).get('data_freshness')
            if data:lines.extend([f'Fingerprint/database date: {data["date"] or "unavailable"} | age days: {data["age_days"]} | basis: {data["date_basis"]}. File dates do not prove current upstream coverage.', ''])
            for warning in run.get('result',{}).get('warnings',[]):lines.extend(['Warning: '+warning,''])
    if not snapshot['findings']:
        lines.extend(['No findings recorded. This does not establish that the assets are secure.', ''])
    return sanitize('\n'.join(lines))
