"""Hostname-only program policy validation."""
import re
import ipaddress
from urllib.parse import urlsplit, unquote


def hostname(value):
    if not isinstance(value, str):
        raise ValueError('Scope values must be strings')
    parsed = urlsplit(value if '://' in value else 'https://' + value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f'Invalid target: {value}')
    # This first version uses hostname scope only, never path or port rules.
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment or parsed.port is not None:
        raise ValueError('Only hostname scope is supported; path and port rules require a later version')
    host = parsed.hostname.rstrip('.').encode('idna').decode().lower()
    if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
        raise ValueError('Expected a valid DNS hostname or IPv4 address')
    return host


def matches(host, rule):
    if '/' in rule:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    if rule.startswith('*.'):
        base = hostname(rule[2:])
        return host.endswith('.' + base)
    return host == hostname(rule)


def validate_host_rule(rule):
    if '/' in rule:
        network=ipaddress.ip_network(rule,strict=False)
        if network.version!=4:
            raise ValueError('IPv6 scope is not supported yet')
    else:
        hostname(rule[2:] if rule.startswith('*.') else rule)


def canonical_path(value):
    path=value
    for _ in range(4):
        decoded=unquote(path)
        if decoded==path:
            break
        path=decoded
    if '%' in path or '\\' in path or any(ord(c)<32 for c in path) or any(part in {'.','..'} for part in path.split('/')):
        raise ValueError('Ambiguous encoded path')
    return path or '/'


def parse_asset_rule(value, exclusion=False):
    if not isinstance(value,str) or not value or any(ord(c)<32 or c=='\\' for c in value):
        raise ValueError('Invalid asset scope rule')
    if '://' not in value:
        validate_host_rule(value)
        return {'kind':'host','host':value.lower().rstrip('.')}
    parsed=urlsplit(value)
    if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Unsupported URL scope rule')
    host=parsed.hostname
    validate_host_rule(host)
    host=('*.'+hostname(host[2:])) if host.startswith('*.') else hostname(host)
    path=parsed.path or '/'
    prefix=exclusion or path=='/' or path.endswith('/*')
    if path.endswith('/*'):
        path=path[:-2] or '/'
    if '*' in path:
        raise ValueError('Only terminal /* URL wildcards are supported')
    port=parsed.port or (443 if parsed.scheme=='https' else 80)
    if parsed.port==0:
        raise ValueError('Invalid URL scope port')
    return {'kind':'url','host':host,'scheme':parsed.scheme,'port':port,'path':canonical_path(path),'prefix':prefix}


def asset_rule_matches(url, rule, exclusion=False):
    rule=parse_asset_rule(rule,exclusion)
    parsed=urlsplit(url)
    if not matches(hostname(parsed.hostname),rule['host']):
        return False
    if rule['kind']=='host':
        return True
    if parsed.scheme!=rule['scheme'] or (parsed.port or (443 if parsed.scheme=='https' else 80))!=rule['port']:
        return False
    path=canonical_path(parsed.path)
    return path==rule['path'] or (rule['prefix'] and (rule['path']=='/' or path.startswith(rule['path'].rstrip('/')+'/')))


def authorize_asset_url(program,url):
    rules=program.get('asset_scope')
    if rules is None:
        return
    if any(asset_rule_matches(url,r,True) for r in rules['exclude']) or not any(asset_rule_matches(url,r) for r in rules['include']):
        raise ValueError('URL is outside approved asset scope')


def authorize_resolved_ips(program,ips):
    rules=list(program['exclude'])
    for value in program.get('asset_scope',{}).get('exclude',[]):
        rule=parse_asset_rule(value,True)
        if rule['kind']=='host':
            rules.append(rule['host'])
    if any(matches(ip,rule) for ip in ips for rule in rules):
        raise ValueError('Resolved address is explicitly out of scope')


def automation_allowed(program,tool):
    controls=program.get('automation',{})
    if not isinstance(controls,dict) or set(controls)-{'allowed','tools'}:
        raise ValueError('Invalid automation policy')
    if controls.get('allowed',True) is not True:
        raise ValueError('Program prohibits automated activity')
    tools=controls.get('tools')
    if tools is not None and (not isinstance(tools,list) or not all(isinstance(t,str) for t in tools)):
        raise ValueError('automation.tools must be an array')
    if tools is not None and tool not in tools:
        raise ValueError(f'Program does not permit tool: {tool}')


def validate_program(program):
    if not isinstance(program, dict):
        raise ValueError('Program must be an object')
    if program.get('authorized') is not True:
        raise ValueError('Program must explicitly record authorized: true')
    review=program.get('scope_review')
    if review is not None and (not isinstance(review,dict) or review.get('complete') is not True or review.get('blockers')):
        raise ValueError('Imported scope requires completed review with no unresolved blockers')
    for field in ('include', 'exclude'):
        if not isinstance(program.get(field), list) or not all(isinstance(x, str) for x in program[field]):
            raise ValueError(f'{field} must be a list of hostname rules')
        for rule in program[field]:
            validate_host_rule(rule)
    asset_scope=program.get('asset_scope')
    if asset_scope is not None:
        if not isinstance(asset_scope,dict) or set(asset_scope)!={'include','exclude'}:
            raise ValueError('asset_scope requires include and exclude arrays')
        for key in ('include','exclude'):
            if not isinstance(asset_scope[key],list) or (key=='include' and not asset_scope[key]):
                raise ValueError('Invalid asset scope array')
            for rule in asset_scope[key]:
                parse_asset_rule(rule,key=='exclude')
    allowed = program.get('allowed_modes', ['passive', 'manual'])
    if not isinstance(allowed, list) or not all(x in {'passive', 'active', 'manual'} for x in allowed):
        raise ValueError('Invalid allowed_modes')
    if not program['include']:
        raise ValueError('At least one included hostname rule is required')
    return allowed


def plan(program, target, entries):
    allowed = validate_program(program)
    host = hostname(target)
    if any(matches(host, r) for r in program['exclude']) or not any(matches(host, r) for r in program['include']):
        raise ValueError(f'Target is outside approved scope: {host}')
    return {
        'target': host,
        'execution': 'plan-only; no network requests or tools executed',
        'scope_model': 'hostname only; wildcard excludes apex; exclusions take precedence',
        'tasks': [{**entry, 'status': 'planned' if entry['mode'] in allowed else 'blocked-by-program-policy',
                   'implementation': 'reference-only; no executable adapter yet'} for entry in entries],
    }

