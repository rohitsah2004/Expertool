"""One authorization path for direct and proxied connections."""
import hashlib
import ipaddress
import json
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .scope import authorize_resolved_ips, matches, parse_asset_rule
from .budgets import LIMITS


class EgressDenied(ValueError):
    pass


def egress_settings(policy):
    raw = policy.get('egress', {})
    defaults = {'global_concurrency':4, 'target_concurrency':1, 'resolved_ip_ranges':[],
                'private_networks':[], 'tunnel_seconds':15, 'tunnel_bytes':2097152}
    if not isinstance(raw,dict) or set(raw)-set(defaults):
        raise ValueError('Unknown egress setting')
    config = {**defaults, **raw}
    for key,low,high in [('global_concurrency',1,16),('target_concurrency',1,8),('tunnel_seconds',1,60),('tunnel_bytes',1024,8388608)]:
        if type(config[key]) is not int or not low <= config[key] <= high:
            raise ValueError(f'Invalid egress {key}')
    for key in ('resolved_ip_ranges','private_networks'):
        if not isinstance(config[key],list):
            raise ValueError(f'{key} must be an array')
        for cidr in config[key]:
            ipaddress.ip_network(cidr,strict=False)
    return config


def revision(policy):
    return hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(',',':')).encode()).hexdigest()


@dataclass
class Permit:
    url: str
    host: str
    port: int
    ips: list
    config: dict
    egress: dict
    policy: dict
    version: str


class PolicySource:
    def __init__(self, policy, workspace=None, program=None):
        self.static = policy
        self.workspace = workspace
        self.program = program
        self.namespace = ((workspace.path,program) if workspace else ('static',id(policy)))

    def load(self):
        if self.workspace is None:
            return self.static
        # Independent connections allow request handlers to see committed revocations.
        with self.workspace.reader() as connection:
            row=connection.execute('SELECT policy FROM programs WHERE name=?',(self.program,)).fetchone()
        if row is None:
            raise EgressDenied('Program removed')
        return json.loads(row['policy'])

    def audit(self, *, host, port, decision, reason, tool, run_id, version=None, ip=None, transport='http'):
        if self.workspace is not None:
            self.workspace.audit_egress(self.program,host,port,decision,reason,tool,run_id,version,ip,transport)


class EgressGuard:
    def __init__(self, source, tool='http',run_id=None):
        self.source,self.tool,self.run_id=source,tool,run_id
        self.started=time.monotonic()
        self.expected_version=None

    def audit(self,permit=None,decision='denied',reason='policy-denied',host=None,port=None,transport='http',version=None):
        self.source.audit(host=permit.host if permit else host,port=permit.port if permit else port,
            decision=decision,reason=reason,tool=self.tool,run_id=self.run_id,
            version=permit.version if permit else version,ip=permit.ips[0] if permit else None,transport=transport)

    def configuration(self,policy):
        from .execution import settings
        return settings(policy,tool=self.tool)

    def authorize(self,url,connect=False,headers_supported=False):
        from .execution import settings, checked_url
        host,port=None,None
        policy=None
        try:
            parsed=urlsplit(url)
            host=parsed.hostname
            port=parsed.port or (443 if parsed.scheme=='https' else 80)
            if not host or host.endswith('.') or ':' in host or '%' in host:
                raise EgressDenied('Ambiguous or unsupported host notation')
            # inet_aton-style decimal/octal/hex forms must never be treated as DNS.
            numeric=host.split('.')
            if all(part.isdigit() or (part.lower().startswith('0x') and all(c in '0123456789abcdef' for c in part[2:].lower())) for part in numeric):
                try:
                    literal=ipaddress.IPv4Address(host)
                    if str(literal)!=host:raise ValueError('Noncanonical IPv4')
                except ValueError:raise EgressDenied('Noncanonical IPv4 notation') from None
            policy=self.source.load()
            if self.expected_version is not None and revision(policy)!=self.expected_version:
                raise EgressDenied('Scanner policy changed; restart required')
            if self.tool in {'httpx','nuclei','whatweb','wpscan'} and self.tool not in policy.get('scanners',{}).get('enabled',[]):
                raise EgressDenied('Scanner disabled by current policy')
            config=self.configuration(policy)
            if time.monotonic()-self.started>=config['max_seconds']:
                raise EgressDenied('Run time budget exhausted')
            config_egress=egress_settings(policy)
            canonical=checked_url(policy,url,config)
            if connect:
                self.check_connect(policy,canonical,config,headers_supported)
            answers=[]
            errors=[]
            def resolve():
                try:
                    answers.extend(socket.getaddrinfo(host,port,type=socket.SOCK_STREAM))
                except OSError as error:
                    errors.append(error)
            resolver=threading.Thread(target=resolve,daemon=True)
            resolver.start();resolver.join(config['timeout'])
            if resolver.is_alive():
                raise EgressDenied('DNS timeout')
            if errors or not answers:
                raise EgressDenied('DNS unavailable')
            ips=sorted({answer[4][0] for answer in answers})
            self.check_addresses(policy,config,config_egress,ips)
            ips=[ip for ip in ips if ipaddress.ip_address(ip).version==4]
            if not ips:raise EgressDenied('No supported validated IPv4 destination')
            # A DNS response never authorizes a stale policy's connection.
            if revision(self.source.load()) != revision(policy):
                raise EgressDenied('Policy changed during resolution; retry')
            return Permit(canonical,host,port,ips,config,config_egress,policy,revision(policy))
        except (ValueError,TypeError,OSError,sqlite3.Error) as error:
            # Fixed reasons only: exception messages may contain target paths/tokens.
            self.audit(decision='denied',reason='connect-policy-denied' if connect else 'policy-denied',host=host,port=port,transport='connect' if connect else 'http',version=revision(policy) if isinstance(policy,dict) else None)
            raise EgressDenied('Egress policy denied request') from error

    @staticmethod
    def check_addresses(policy,config,egress,ips):
        authorize_resolved_ips(policy,ips)
        for value in ips:
            ip=ipaddress.ip_address(value)
            if '%' in value or (ip.version==6 and ip.ipv4_mapped is not None):raise EgressDenied('Mapped or zone-qualified addresses denied')
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                raise EgressDenied('Special-use destination denied')
            if egress['resolved_ip_ranges'] and not any(ip in ipaddress.ip_network(c,strict=False) for c in egress['resolved_ip_ranges']):
                raise EgressDenied('Resolved address not allowed')
            if not ip.is_global:
                explicit=any(matches(value,r) for r in policy['include']) or any(ip in ipaddress.ip_network(c,strict=False) for c in egress['private_networks'])
                if not config['allow_private'] or not explicit:
                    raise EgressDenied('Private address requires explicit scope and opt-in')

    @staticmethod
    def check_connect(policy,url,config,headers_supported):
        if config['path_prefixes']!=['/'] or config['excluded_paths']:
            raise EgressDenied('CONNECT cannot enforce path restrictions')
        parsed=urlsplit(url)
        port=parsed.port or 443
        included=policy.get('asset_scope',{}).get('include',policy['include'])
        excluded=policy.get('asset_scope',{}).get('exclude',[])
        for value in excluded:
            rule=parse_asset_rule(value,True)
            if matches(parsed.hostname,rule['host']) and (rule['kind']=='host' or (rule['scheme']=='https' and rule['port']==port)):
                raise EgressDenied('CONNECT cannot enforce an excluded HTTPS path')
        whole_origin=False
        for value in included:
            rule=parse_asset_rule(value)
            if matches(parsed.hostname,rule['host']) and (rule['kind']=='host' or
                (rule['scheme']=='https' and rule['port']==port and rule['path']=='/' and rule['prefix'])):
                whole_origin=True
        if not whole_origin:
            raise EgressDenied('CONNECT requires complete HTTPS origin scope')
        identification=config['request_headers'] or 'user_agent' in policy.get('scan',{})
        if identification and not headers_supported:
            raise EgressDenied('CONNECT cannot inject required identification headers')

    def unchanged(self,permit):
        try:return revision(self.source.load())==permit.version and time.monotonic()-self.started<permit.config['max_seconds']
        except (ValueError,OSError,sqlite3.Error):return False

    def reserve(self,permit):
        return LIMITS.acquire(self.source.namespace,permit.host,permit.config,permit.egress,self.run_id)
