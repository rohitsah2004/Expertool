"""Explicit third-party blind CONNECT permission; never a scope-check fallback."""
from datetime import datetime
import copy
import ipaddress
from urllib.parse import urlsplit
from .scope import hostname,matches,parse_asset_rule
from .egress import EgressGuard,PolicySource,EgressDenied,revision

# No downloaded/partial PSL is trusted. Unreviewed wildcard roots fail closed;
# exact hosts support other providers without making public-suffix assumptions.
REVIEWED_WILDCARD_ROOTS={'gstatic.com'}

def approval(value):
    if not isinstance(value.get('approved_by'),str) or not value['approved_by'].strip() or len(value['approved_by'])>200:raise ValueError('Approval requires approved_by')
    try:
        date=datetime.fromisoformat(value['approved_at'].replace('Z','+00:00'))
        if date.tzinfo is None:raise ValueError()
    except (KeyError,AttributeError,TypeError,ValueError):raise ValueError('Approval requires timezone-aware approved_at') from None

def host_rules(policy,key):
    result=list(policy[key])
    result.extend(parse_asset_rule(rule,key=='exclude')['host'] for rule in policy.get('asset_scope',{}).get(key,[]))
    return result

def excluded(policy,host):return any(matches(host,rule) for rule in host_rules(policy,'exclude'))
def in_scope_host(policy,host):return any(matches(host,rule) for rule in host_rules(policy,'include'))

def controls(policy):
    value=policy.get('interception',{}).get('passthrough',False)
    if value is False:return {'enabled':False,'hosts':[],'ports':[],'warnings':[]}
    if not isinstance(value,dict) or set(value)-{'enabled','hosts','ports','approved_by','approved_at'} or type(value.get('enabled')) is not bool:raise ValueError('Invalid passthrough approval')
    if not value['enabled']:
        if value.get('hosts') or value.get('ports'):raise ValueError('Disabled passthrough must have no active allowlist')
        return {'enabled':False,'hosts':[],'ports':[],'warnings':[]}
    approval(value);hosts=value.get('hosts');ports=value.get('ports')
    if not isinstance(hosts,list) or not 1<=len(hosts)<=50 or not isinstance(ports,list) or not ports or any(type(p) is not int or not 1<=p<=65535 for p in ports):raise ValueError('Invalid passthrough hosts/ports')
    for rule in hosts:
        if not isinstance(rule,str):raise ValueError('Invalid passthrough host')
        base=rule[2:] if rule.startswith('*.') else rule
        if hostname(base)!=base or '*' in base:raise ValueError('Canonical hostnames required')
        try:ipaddress.ip_address(base)
        except ValueError:pass
        else:raise ValueError('Passthrough allowlist requires DNS hostnames')
        if rule.startswith('*.') and base not in REVIEWED_WILDCARD_ROOTS:raise ValueError('Unreviewed wildcard root; use exact hosts (public suffixes are refused)')
        if any(matches(base,ex) or matches(ex[2:] if ex.startswith('*.') else ex,rule) for ex in host_rules(policy,'exclude') if '/' not in ex):raise ValueError('Passthrough overlaps a program exclusion')
        if in_scope_host(policy,base):raise ValueError('Passthrough must not overlap in-scope hosts')
    warnings=[]
    if len(hosts)>10:warnings.append('Large third-party allowlist; review necessity and program rules')
    if any(h.startswith('*.') for h in hosts):warnings.append('Wildcard passthrough permits multiple third-party hosts without inspection')
    return {**value,'warnings':warnings}


class PassthroughSource:
    def __init__(self,parent):self.parent=parent;self.namespace=parent.namespace
    def load(self):
        original=self.parent.load();config=controls(original)
        if not config['enabled']:raise EgressDenied('Passthrough disabled')
        from .manual_policy import interception_settings
        interception_settings(original)
        policy=copy.deepcopy(original)
        policy['include']=config['hosts'];policy['asset_scope']={'include':config['hosts'],'exclude':host_rules(original,'exclude')}
        policy['allowed_modes']=['active'];policy['automation']={'allowed':True,'tools':['intercept-passthrough']}
        policy['scan']={**original.get('scan',{}),'ports':config['ports'],'allow_private':False,'path_prefixes':['/'],'excluded_paths':[],'request_headers':{}}
        return policy
    def audit(self,**kwargs):self.parent.audit(**kwargs)


def authorize(guard,host,port):
    original=guard.source.load();config=controls(original)
    if excluded(original,host) or in_scope_host(original,host) or not config['enabled'] or port not in config['ports'] or not any(matches(host,rule) for rule in config['hosts']):raise EgressDenied('Blind passthrough refused')
    broker=EgressGuard(PassthroughSource(guard.source),'intercept-passthrough',guard.run_id)
    broker.started=guard.started
    permit=broker.authorize(f'https://{host}:{port}/')
    # Passthrough never inherits private-network exceptions from the program.
    if any(not ipaddress.ip_address(ip).is_global for ip in permit.ips):raise EgressDenied('Passthrough requires public IPv4')
    if revision(guard.source.load())!=revision(original):raise EgressDenied('Policy changed')
    permit.policy=original;permit.version=revision(original)
    return permit
