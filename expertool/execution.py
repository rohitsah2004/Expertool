"""Bounded read-only HTTP assessments with per-request scope and destination checks."""
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import threading
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from .scope import plan, validate_program, authorize_asset_url, authorize_resolved_ips, automation_allowed, canonical_path
from .workspace import normalize_url, now, inspect_headers

DEFAULTS = {'max_requests': 30, 'max_depth': 2, 'rate_per_second': 1, 'timeout': 5,
            'max_response_bytes': 262144, 'max_seconds': 120, 'ports': [80, 443],
            'allow_private': False, 'path_prefixes': ['/'], 'excluded_paths': [],
            'user_agent':'Expertool/0.3 authorized-assessment','request_headers':{}}
LIMITS = {'max_requests': (1, 500), 'max_depth': (0, 5), 'rate_per_second': (0.1, 10),
          'timeout': (0.1, 30), 'max_response_bytes': (1024, 2097152), 'max_seconds': (1, 600)}


def settings(policy, tool='http'):
    validate_program(policy)
    automation_allowed(policy,tool)
    if 'active' not in policy.get('allowed_modes', []):
        raise ValueError('Live requests require active in program allowed_modes')
    return scan_settings(policy)


def scan_settings(policy):
    """Validate shared bounds only; callers must establish their own permissions."""
    raw = policy.get('scan', {})
    if not isinstance(raw, dict) or set(raw) - set(DEFAULTS):
        raise ValueError('Unknown scan policy setting')
    config = {**DEFAULTS, **raw}
    for key, (minimum, maximum) in LIMITS.items():
        value = config[key]
        if type(value) not in (int, float) or not minimum <= value <= maximum:
            raise ValueError(f'{key} must be between {minimum} and {maximum}')
    for key in ('max_requests', 'max_depth', 'max_response_bytes'):
        if type(config[key]) is not int:
            raise ValueError(f'{key} must be an integer')
    if type(config['allow_private']) is not bool:
        raise ValueError('allow_private must be boolean')
    if not isinstance(config['ports'], list) or not config['ports'] or any(type(p) is not int or not 1 <= p <= 65535 for p in config['ports']):
        raise ValueError('ports must be a nonempty array of TCP ports')
    for key in ('path_prefixes', 'excluded_paths'):
        if not isinstance(config[key], list) or any(not isinstance(p, str) or not p.startswith('/') or '?' in p or '#' in p for p in config[key]):
            raise ValueError(f'{key} must be an array of absolute path prefixes')
    if not config['path_prefixes']:
        raise ValueError('At least one path prefix is required')
    if not isinstance(config['user_agent'],str) or not config['user_agent'] or any(ord(c)<32 or ord(c)>126 for c in config['user_agent']):
        raise ValueError('Invalid user_agent')
    if not isinstance(config['request_headers'],dict):
        raise ValueError('request_headers must be an object')
    forbidden={'host','authorization','cookie','x-api-key','proxy-authorization','connection','content-length','transfer-encoding','user-agent','accept-encoding','upgrade','expect'}
    seen=set()
    for key,value in config['request_headers'].items():
        if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9-]+',key) or key.lower() in forbidden or key.lower() in seen:
            raise ValueError('Unsupported or duplicate request header; use auth profiles for credentials')
        if not isinstance(value,str) or any(ord(c)<32 or ord(c)>126 for c in value):
            raise ValueError('Invalid request header value')
        seen.add(key.lower())
    return config


def path_matches(path, prefix):
    return prefix == '/' or path == prefix.rstrip('/') or path.startswith(prefix.rstrip('/') + '/')


def checked_url(policy, value, config=None):
    config = config or settings(policy)
    if not isinstance(value, str) or any(ord(c) < 32 or c == '\\' for c in value):
        raise ValueError('Invalid URL characters')
    url, host = normalize_url(value)
    if urlsplit(value).scheme not in {'http', 'https'}:
        raise ValueError('Live targets require explicit HTTP(S) URLs')
    plan(policy, host, [])
    authorize_asset_url(policy,url)
    parsed = urlsplit(url)
    if (parsed.port or (443 if parsed.scheme == 'https' else 80)) not in config['ports']:
        raise ValueError('Port is outside program scan policy')
    path = canonical_path(parsed.path)
    if not any(path_matches(path, p) for p in config['path_prefixes']) or any(path_matches(path, p) for p in config['excluded_paths']):
        raise ValueError('Path is outside program scan policy')
    if any(word in path.lower().split('/') for word in ('logout', 'signout', 'delete', 'remove', 'unsubscribe')):
        raise ValueError('Potential state-changing navigation skipped')
    return url


def load_auth(path):
    """Profile contains environment variable names, never credential values."""
    if path is None:
        return None
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or set(data) - {'name', 'origin', 'headers_env'}:
        raise ValueError('Auth profile supports name, origin and headers_env only')
    origin = checked_origin(data.get('origin'))
    mapping = data.get('headers_env')
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError('Auth profile requires headers_env')
    headers = {}
    for header, variable in mapping.items():
        if not isinstance(header, str) or header.lower() not in {'authorization', 'cookie', 'x-api-key'}:
            raise ValueError('Auth profile header is not supported')
        if not isinstance(variable, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', variable):
            raise ValueError('Auth profile must reference an environment variable')
        value = os.environ.get(variable)
        if not value or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError(f'Missing or invalid auth environment variable: {variable}')
        headers[header] = value
    from .redaction import register_credentials
    register_credentials(headers)
    return {'name': str(data.get('name', 'authenticated'))[:80], 'origin': origin, 'headers': headers}


def origin_of(value):
    parsed = urlsplit(value)
    return f'{parsed.scheme}://{parsed.netloc}'


def checked_origin(value):
    url, _ = normalize_url(value)
    parsed = urlsplit(url)
    if parsed.path != '/' or parsed.query:
        raise ValueError('Auth origin must not contain path or query')
    return f'{parsed.scheme}://{parsed.netloc}'


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    cookies: list
    body: bytes
    truncated: bool
    ip: str


class Client:
    def __init__(self, policy, auth=None, workspace=None, program=None, run_id=None, proxy=None):
        from .egress import EgressGuard, PolicySource
        from .redaction import register_credentials
        self.policy, self.config, self.auth = policy, settings(policy), auth
        self.guard=EgressGuard(PolicySource(policy,workspace,program),'http',run_id) if workspace else None
        self.proxy=proxy
        register_credentials(auth['headers'] if auth else {})
        self.started = time.monotonic()
        self.last = 0
        self.requests = 0

    def get(self, url, authenticated=True, extra_headers=None):
        try:
            return self._get(url,authenticated,extra_headers)
        except (ValueError,OSError,http.client.HTTPException):
            if self.guard:
                try:
                    parsed=urlsplit(url)
                    host,port=parsed.hostname,parsed.port or (443 if parsed.scheme=='https' else 80)
                except (ValueError,TypeError):host,port=None,None
                self.guard.audit(host=host,port=port,reason='client-request-refused-or-failed')
            raise

    def _get(self, url, authenticated=True, extra_headers=None):
        from .redaction import register_credentials
        register_credentials(self.auth['headers'] if self.auth else {})
        permit=self.guard.authorize(url) if self.guard else None
        if permit:
            previous=self.config
            self.policy,self.config=permit.policy,permit.config
            for key in ('max_requests','max_seconds','timeout','max_response_bytes'):
                self.config[key]=min(previous[key],self.config[key])
        url = checked_url(self.policy, url, self.config)
        if self.requests >= self.config['max_requests']:
            raise ValueError('Request budget exhausted')
        deadline = self.started + self.config['max_seconds']
        delay = max(0, 1 / self.config['rate_per_second'] - (time.monotonic() - self.last))
        if time.monotonic() + delay >= deadline:
            raise ValueError('Run time budget exhausted')
        time.sleep(delay)
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        # Resolve once, validate all answers, and connect to that address directly.
        # TLS still validates the original hostname. Proxies are never inherited.
        if permit:
            ips=permit.ips
        else:
            resolved = []
            errors = []
            def resolve():
                try:
                    resolved.extend(socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM))
                except OSError as error:
                    errors.append(error)
            resolver = threading.Thread(target=resolve, daemon=True)
            resolver.start()
            resolver.join(min(self.config['timeout'], max(0, deadline-time.monotonic())))
            if resolver.is_alive():
                raise TimeoutError('DNS lookup exceeded request budget')
            if errors:
                raise errors[0]
            answers = resolved
            ips = sorted({a[4][0] for a in answers})
            authorize_resolved_ips(self.policy,ips)
            if any(ipaddress.ip_address(ip).is_link_local or ipaddress.ip_address(ip).is_multicast or ipaddress.ip_address(ip).is_unspecified for ip in ips):
                raise ValueError('Link-local, multicast and unspecified destinations are blocked')
            if not ips or (not self.config['allow_private'] and any(not ipaddress.ip_address(ip).is_global for ip in ips)):
                raise ValueError('Non-public destination blocked by scan policy')
        headers = {'User-Agent': self.config['user_agent'], 'Accept': 'text/html,application/json;q=0.9,*/*;q=0.1', 'Accept-Encoding': 'identity'}
        headers.update(self.config['request_headers'])
        if authenticated and self.auth:
            if origin_of(url) != self.auth['origin']:
                raise ValueError('Credential origin mismatch')
            if parsed.scheme != 'https' and not (self.config['allow_private'] and all(ipaddress.ip_address(ip).is_loopback for ip in ips)):
                raise ValueError('Credentials require HTTPS (except explicit loopback fixtures)')
            headers.update(self.auth['headers'])
        headers.update(extra_headers or {})
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Run time budget exhausted')
        timeout = min(self.config['timeout'], remaining)
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        response = None
        timer = None
        expired = threading.Event()
        watch_stop=threading.Event()
        lease=None
        leased=False
        self.requests += 1
        self.last = time.monotonic()
        try:
            if permit and not self.proxy:
                lease=self.guard.reserve(permit)
                lease.__enter__()
                leased=True
                if not self.guard.unchanged(permit):
                    self.guard.audit(permit,reason='policy-revoked')
                    raise ValueError('Policy revoked before connection')
                self.guard.audit(permit,decision='allowed',reason='authorized',transport='direct')
            if self.proxy:
                if parsed.scheme=='https':
                    connection=http.client.HTTPSConnection(self.proxy.host,self.proxy.port,timeout=timeout,context=ssl.create_default_context())
                    connection.set_tunnel(parsed.hostname,port,headers={'Proxy-Authorization':self.proxy.authorization})
                else:
                    connection=http.client.HTTPConnection(self.proxy.host,self.proxy.port,timeout=timeout)
                    headers['Proxy-Authorization']=self.proxy.authorization
                connection.connect()
            else:
                connection.sock = socket.create_connection((ips[0], port), timeout=timeout)
                if parsed.scheme == 'https':
                    connection.sock = ssl.create_default_context().wrap_socket(connection.sock, server_hostname=parsed.hostname)
            transport = connection.sock
            if permit:
                def watch_policy():
                    while not watch_stop.wait(.1):
                        try:
                            changed=not self.guard.unchanged(permit)
                        except Exception:
                            changed=True
                        if changed:
                            self.guard.audit(permit,decision='denied',reason='policy-revoked',transport='direct')
                            try: transport.shutdown(socket.SHUT_RDWR)
                            except OSError: pass
                            break
                threading.Thread(target=watch_policy,daemon=True).start()
            def expire():
                expired.set()
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(min(self.config['timeout'], max(0.01, deadline-time.monotonic())), expire)
            timer.daemon = True
            timer.start()
            request_path = parsed.path + ('?' + parsed.query if parsed.query else '')
            connection.request('GET', url if self.proxy and parsed.scheme=='http' else request_path, headers=headers)
            response = connection.getresponse()
            # Recompute remaining time on every read, not only at connection setup.
            raw = bytearray()
            maximum = self.config['max_response_bytes']
            while len(raw) <= maximum:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Run time budget exhausted')
                transport.settimeout(min(self.config['timeout'], remaining))
                block = response.read1(min(16384, maximum + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                if response.isclosed():
                    break
            if expired.is_set():
                raise TimeoutError('Request exceeded its time budget')
            return Response(url, response.status, {k.lower(): v for k, v in response.getheaders()},
                            response.headers.get_all('Set-Cookie') or [], bytes(raw[:maximum]), len(raw) > maximum, ips[0])
        finally:
            watch_stop.set()
            if leased:
                lease.__exit__(None,None,None)
            if timer:
                timer.cancel()
            if response:
                response.close()
            connection.close()


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.title = ''
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {'a', 'link', 'script'}:
            target = attrs.get('href' if tag != 'script' else 'src')
            if target:
                self.links.append(target)
        if tag == 'form':
            self.forms.append({'method': attrs.get('method', 'get').upper(), 'action': attrs.get('action', '')})
        if tag == 'title':
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data[:200]


def load_checks(path):
    if path is None:
        return []
    checks = json.loads(Path(path).read_text())
    if not isinstance(checks, list) or len(checks) > 50:
        raise ValueError('Custom checks must be an array of at most 50 definitions')
    ids = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) - {'id', 'name', 'severity', 'path', 'match'}:
            raise ValueError('Invalid custom check fields')
        for key in ('id', 'name', 'path'):
            if not isinstance(check.get(key), str) or not check[key]:
                raise ValueError(f'Custom check requires {key}')
        if check['id'] in ids or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', check['id']):
            raise ValueError('Custom check IDs must be unique simple identifiers')
        ids.add(check['id'])
        if not check['path'].startswith('/') or check['path'].startswith('//') or '#' in check['path']:
            raise ValueError('Custom check path must be relative to target origin')
        if check.get('severity') not in {'info', 'low', 'medium', 'high', 'critical'}:
            raise ValueError('Invalid custom check severity')
        match = check.get('match')
        if not isinstance(match, dict) or not match or set(match) - {'status', 'header', 'body_contains'}:
            raise ValueError('Custom matcher needs status, header or body_contains')
        if 'status' in match and (type(match['status']) is not int or not 100 <= match['status'] <= 599):
            raise ValueError('Invalid custom status')
        if 'body_contains' in match and (not isinstance(match['body_contains'], str) or not match['body_contains'] or len(match['body_contains']) > 4096):
            raise ValueError('Invalid custom body matcher')
        if 'header' in match and (not isinstance(match['header'], dict) or not match['header'] or not all(isinstance(k, str) and isinstance(v, str) for k, v in match['header'].items())):
            raise ValueError('Header matcher must map header names to substrings')
    return checks


def custom_matches(check, response):
    match = check['match']
    return (('status' not in match or response.status == match['status']) and
            ('body_contains' not in match or match['body_contains'].encode() in response.body) and
            all(value.lower() in response.headers.get(key.lower(), '').lower() for key, value in match.get('header', {}).items()))


def analyze(response):
    result = inspect_headers([{'url': response.url, 'headers': response.headers}])[0]
    result['metadata'] = {'status_code': response.status, 'server': response.headers.get('server', '')[:200],
                          'content_type': response.headers.get('content-type', '')[:120], 'body_sha256': hashlib.sha256(response.body).hexdigest(),
                          'bytes_read': len(response.body), 'truncated': response.truncated, 'resolved_ip': response.ip}
    for finding in result['findings']:
        finding['evidence'] = finding['evidence'].replace('Supplied capture', 'Live GET response')
    html = 'text/html' in response.headers.get('content-type', '')
    if html and not response.headers.get('content-security-policy'):
        result['findings'].append({'check_id': 'headers.csp', 'title': 'HTML response lacks Content Security Policy', 'severity': 'info', 'evidence': 'Live HTML response had no CSP header. This is a posture observation, not proof of script injection.'})
    if html and not response.headers.get('x-frame-options') and 'frame-ancestors' not in response.headers.get('content-security-policy', '').lower():
        result['findings'].append({'check_id': 'headers.framing', 'title': 'HTML response has no explicit framing restriction', 'severity': 'info', 'evidence': 'Neither X-Frame-Options nor CSP frame-ancestors was observed. Clickjacking impact requires manual validation.'})
    for attribute in ('secure', 'httponly'):
        if any(attribute not in {p.strip().split('=', 1)[0].lower() for p in cookie.split(';')[1:]} for cookie in response.cookies):
            result['findings'].append({'check_id': 'cookies.' + attribute, 'title': f'A response cookie lacks {attribute}', 'severity': 'info', 'evidence': f'At least one Set-Cookie lacked {attribute}. Cookie values and names omitted; whether it is security-sensitive is unverified.'})
    return result


def redact(value, secrets):
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, '[REDACTED]')
        return value
    if isinstance(value, dict):
        return {k: redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    return value


def scan(workspace, program, seeds, auth=None, checks=None, crawl=True, compare_auth=False, time_budget=None, proxy=None):
    policy = workspace.policy(program)
    client = Client(policy, auth, workspace=workspace,program=program,proxy=proxy)
    if time_budget is not None:
        if time_budget <= 0:
            raise ValueError('Pipeline time budget exhausted')
        client.config['max_seconds'] = min(client.config['max_seconds'], time_budget)
    seeds = [checked_url(policy, seed, client.config) for seed in seeds]
    if not seeds:
        raise ValueError('At least one seed URL required')
    origins = {origin_of(url) for url in seeds}
    if auth and (len(origins) != 1 or auth['origin'] not in origins):
        raise ValueError('Authenticated runs must have one origin matching the profile')
    if compare_auth and not auth:
        raise ValueError('Auth comparison requires a profile')
    checks = checks or []
    if auth and any(secret in seed for secret in auth['headers'].values() for seed in seeds):
        raise ValueError('Credential values must not appear in target URLs')
    queue = deque((url, 0) for url in seeds)
    custom_by_url = {}
    for origin in origins:
        for check in checks:
            url = checked_url(policy, origin + check['path'], client.config)
            custom_by_url.setdefault(url, []).append(check)
            queue.append((url, 0))
    run_id = workspace.start_run(program, 'http', {'seeds': seeds, 'crawl': crawl, 'auth': auth['name'] if auth else None, 'custom_checks': [c['id'] for c in checks]})
    client.guard.run_id=run_id
    records, seen, events = [], set(), []
    status = 'completed'
    try:
        while queue:
            if client.requests >= client.config['max_requests'] or time.monotonic() - client.started >= client.config['max_seconds']:
                status = 'budget-limited'
                break
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                response = client.get(url)
                record = analyze(response)
                record['metadata']['run_id'] = run_id
                record['metadata']['auth_profile'] = auth['name'] if auth else None
                for check in custom_by_url.get(url, []):
                    if custom_matches(check, response):
                        record['findings'].append({'check_id': 'custom.' + check['id'], 'title': check['name'], 'severity': check['severity'],
                            'evidence': f'Custom GET matcher {check["id"]} matched at status {response.status}; response SHA256 {record["metadata"]["body_sha256"]}. Matcher success does not independently establish exploit impact.'})
                if compare_auth:
                    try:
                        anonymous = client.get(url, authenticated=False)
                        record['metadata']['auth_comparison'] = {'authenticated_status': response.status, 'anonymous_status': anonymous.status,
                            'body_differs': hashlib.sha256(response.body).digest() != hashlib.sha256(anonymous.body).digest(),
                            'note': 'Response difference is not evidence of an authorization vulnerability'}
                    except (OSError, ValueError, http.client.HTTPException):
                        record['metadata']['auth_comparison'] = {'status': 'inconclusive'}
                parser = Links()
                if 'text/html' in response.headers.get('content-type', '') and response.headers.get('content-encoding', 'identity') == 'identity':
                    parser.feed(response.body.decode('utf-8', errors='replace'))
                    record['metadata']['title'] = parser.title[:200]
                    record['metadata']['forms'] = [{'method': form['method']} for form in parser.forms[:30]]
                if auth:
                    record = redact(record, list(auth['headers'].values()))
                records.append(record)
                targets = []
                if response.status in {301, 302, 303, 307, 308} and response.headers.get('location'):
                    targets.append((urljoin(url, response.headers['location']), depth))
                if crawl and depth < client.config['max_depth']:
                    targets.extend((urljoin(url, link), depth + 1) for link in parser.links[:200])
                for target, target_depth in targets:
                    try:
                        target = checked_url(policy, target, client.config)
                        if auth and any(secret in target for secret in auth['headers'].values()):
                            continue
                        # Keep crawling within seed origins, especially when using credentials.
                        if origin_of(target) not in origins:
                            continue
                        if target not in seen and len(queue) < 1000:
                            queue.append((target, target_depth))
                    except ValueError:
                        events.append({'event': 'navigation-blocked'})
            except (OSError, ValueError, http.client.HTTPException) as error:
                events.append({'event': 'request-failed', 'url': url, 'reason': str(error) if isinstance(error, ValueError) else type(error).__name__})
        imported = workspace.import_records(program, records, f'live:{run_id}')
        result = {'run_id': run_id, 'requests': client.requests, 'pages': len(records), 'events': events, **imported}
        if not records and events:
            status = 'failed'
        workspace.finish_run(run_id, status, result)
        return {**result, 'status': status}
    except BaseException as error:
        workspace.finish_run(run_id, 'cancelled' if isinstance(error, KeyboardInterrupt) else 'failed', {'requests': client.requests, 'pages': len(records)})
        raise


def validate_finding(workspace, finding_id, auth=None, checks=None):
    row = workspace.db.execute('''SELECT f.*, a.url,a.program FROM findings f JOIN assets a ON a.id=f.asset WHERE f.id=?''', (finding_id,)).fetchone()
    if row is None:
        raise ValueError('Unknown finding')
    check_id = row['check_id']
    if check_id.startswith('nuclei:'):
        raise ValueError('Imported Nuclei findings require their original reviewed template; no generic exploit validation is possible')
    if check_id == 'auth.cross-account-canary':
        raise ValueError('Re-run access-check with both controlled account profiles and the original canary')
    policy = workspace.policy(row['program'])
    if check_id.startswith('custom.'):
        original = next((c for c in (checks or []) if 'custom.' + c['id'] == check_id), None)
        if original is None:
            raise ValueError('Supply the original custom check for validation')
        if checked_url(policy, origin_of(row['url']) + original['path']) != row['url']:
            raise ValueError('Custom check path does not match the finding endpoint')
    run_id=workspace.start_run(row['program'],'recheck',{'finding_id':finding_id})
    client = Client(policy, auth,workspace=workspace,program=row['program'],run_id=run_id)
    verdict = 'inconclusive'
    try:
        response = client.get(row['url'])
        matches = [f['check_id'] for f in analyze(response)['findings']]
        if check_id.startswith('custom.'):
            check = next((c for c in (checks or []) if 'custom.' + c['id'] == check_id), None)
            if check is None:
                raise ValueError('Supply the original custom check for validation')
            if custom_matches(check, response):
                matches.append(check_id)
        elif check_id not in {'headers.x-content-type-options','headers.strict-transport-security','headers.csp','headers.framing','cookies.secure','cookies.httponly'}:
            raise ValueError('No validator implemented for this finding type')
        verdict = 'reproduced' if check_id in matches else 'not-reproduced'
        evidence = {'status': response.status, 'body_sha256': hashlib.sha256(response.body).hexdigest(),
                    'note': 'Read-only condition recheck, not proof of exploit impact; review state unchanged'}
    except (OSError, http.client.HTTPException):
        evidence = {'note': 'Network request failed; no conclusion'}
    workspace.record_validation(finding_id, verdict, evidence)
    workspace.finish_run(run_id,'completed',{'finding_id':finding_id,'verdict':verdict})
    return {'finding_id': finding_id, 'verdict': verdict, **evidence}


def access_check(workspace, program, url, owner, other, marker, finding_id=None):
    """Validate an expected account boundary with a caller-supplied owned canary."""
    if not owner or not other or owner['origin'] != other['origin'] or owner['headers'] == other['headers']:
        raise ValueError('Two different controlled account profiles on the same origin are required')
    if not isinstance(marker, str) or len(marker) < 12:
        raise ValueError('Provide a dedicated canary marker of at least 12 characters through the environment')
    from .redaction import register_credentials
    register_credentials(owner['headers']);register_credentials(other['headers'])
    policy = workspace.policy(program)
    url = checked_url(policy, url)
    if origin_of(url) != owner['origin']:
        raise ValueError('Canary endpoint must match both account origins')
    if any(secret in url for profile in (owner, other) for secret in profile['headers'].values()):
        raise ValueError('Credentials must not appear in target URLs')
    run_id = workspace.start_run(program, 'account-boundary', {'url': url, 'owner_profile': owner['name'], 'other_profile': other['name']})
    client = Client(policy, owner,workspace=workspace,program=program,run_id=run_id)
    verdict = 'inconclusive'
    evidence = {'note': 'Controlled canary read across an explicitly expected account boundary; no account enumeration or object mutation performed.'}
    try:
        baseline = client.get(url)
        client.auth = other
        comparison = client.get(url)
        marker_bytes = marker.encode()
        baseline_matches = 200 <= baseline.status < 300 and marker_bytes in baseline.body
        other_matches = 200 <= comparison.status < 300 and marker_bytes in comparison.body
        if baseline_matches:
            verdict = 'reproduced' if other_matches else ('inconclusive' if comparison.truncated else 'not-reproduced')
        evidence.update({'owner_status': baseline.status, 'other_status': comparison.status,
                         'owner_canary_observed': baseline_matches, 'other_canary_observed': other_matches,
                         'canary_sha256': hashlib.sha256(marker_bytes).hexdigest()})
        findings = []
        if verdict == 'reproduced':
            findings.append({'check_id': 'auth.cross-account-canary', 'title': 'Controlled private canary readable by another account',
                             'severity': 'high', 'evidence': json.dumps(evidence, indent=2)})
        workspace.import_records(program, [{'url':url, 'findings':findings,
            'metadata':{'run_id':run_id, 'account_boundary_verdict':verdict}}], f'live:{run_id}')
        if finding_id is None:
            previous = workspace.db.execute('''SELECT f.id FROM findings f JOIN assets a ON a.id=f.asset
                WHERE a.program=? AND a.url=? AND f.check_id='auth.cross-account-canary' ''', (program,url)).fetchone()
            finding_id = previous['id'] if previous else None
        if finding_id is not None:
            workspace.record_validation(finding_id, verdict, evidence)
        result = {'run_id':run_id, 'finding_id':finding_id, 'verdict':verdict, 'requests':client.requests, **evidence}
        workspace.finish_run(run_id, 'completed', result)
        return result
    except BaseException as error:
        workspace.finish_run(run_id, 'cancelled' if isinstance(error, KeyboardInterrupt) else 'failed', {'error':type(error).__name__})
        raise
