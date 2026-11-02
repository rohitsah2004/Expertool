"""Conservative X.509 DNS/IP constraints derived from effective host scope."""
import ipaddress
from .scope import validate_program,parse_asset_rule,matches,hostname


def intersection(a,b):
    try:
        first=ipaddress.ip_network(a,strict=False);second=ipaddress.ip_network(b,strict=False)
        if first.version==second.version and first.overlaps(second):return str(first if first.prefixlen>=second.prefixlen else second)
        return None
    except ValueError:pass
    if a==b:return a
    if not a.startswith('*.') and matches(a,b):return a
    if not b.startswith('*.') and matches(b,a):return b
    if a.startswith('*.') and b.startswith('*.'):
        if a[2:].endswith('.'+b[2:]):return a
        if b[2:].endswith('.'+a[2:]):return b
    return None


def constraints(policy):
    validate_program(policy)
    def canonical(value):
        if '/' in value:return str(ipaddress.ip_network(value,strict=False))
        return '*.'+hostname(value[2:]) if value.startswith('*.') else hostname(value)
    rules=[canonical(value) for value in policy['include']]
    if policy.get('asset_scope'):
        narrow=[parse_asset_rule(v)['host'] for v in policy['asset_scope']['include']]
        rules=[value for a in rules for b in narrow if (value:=intersection(a,b))]
    if not rules or len(rules)>128:raise ValueError('CA requires 1–128 representable effective scope rules')
    exact=set();wild=set();ips=set();excluded_dns=set();excluded_ip={'::/0'}
    for value in rules:
        try:network=ipaddress.ip_network(value,strict=False)
        except ValueError:
            (wild if value.startswith('*.') else exact).add(value[2:] if value.startswith('*.') else value)
        else:
            if network.version!=4:raise ValueError('IPv6 CA scope is unsupported')
            ips.add(str(network))
    for name in exact:
        children=[other for other in exact|wild if other!=name and other.endswith('.'+name)]
        covered=name in wild or any(name.endswith('.'+root) for root in wild)
        if children and not covered:raise ValueError('Exact parent plus selected children cannot be constrained precisely; split programs or use a reviewed subtree scope')
        if not covered:excluded_dns.add('.'+name)
    for raw in policy['exclude']+[parse_asset_rule(v,True)['host'] for v in policy.get('asset_scope',{}).get('exclude',[]) if parse_asset_rule(v,True)['kind']=='host']:
        value=canonical(raw)
        try:network=ipaddress.ip_network(value,strict=False)
        except ValueError:excluded_dns.add('.'+value[2:] if value.startswith('*.') else value)
        else:excluded_ip.add(str(network))
    permitted_dns=exact|{'.'+root for root in wild}
    if not permitted_dns:
        # Contradictory DNS constraints prohibit all DNS SANs in an IP-only CA.
        permitted_dns={'invalid'};excluded_dns.add('invalid')
    if not ips:excluded_ip.add('0.0.0.0/0')
    return {'permitted_dns':sorted(permitted_dns),'excluded_dns':sorted(excluded_dns),
            'permitted_ip':sorted(ips),'excluded_ip':sorted(excluded_ip)}


def extension(value):
    parts=['critical']
    for key in ('permitted_dns','excluded_dns','permitted_ip','excluded_ip'):
        kind='DNS' if key.endswith('dns') else 'IP'
        direction='permitted' if key.startswith('permitted') else 'excluded'
        for item in value[key]:
            if kind=='IP':
                net=ipaddress.ip_network(item);item=str(net.network_address)+'/'+str(net.netmask)
            parts.append(direction+';'+kind+':'+item)
    return ','.join(parts)


def permits_host(value,host):
    try:ip=ipaddress.ip_address(host)
    except ValueError:
        def covers(rule):return host.endswith(rule) if rule.startswith('.') else host==rule or host.endswith('.'+rule)
        return any(covers(r) for r in value['permitted_dns']) and not any(covers(r) for r in value['excluded_dns'])
    return any(ip in ipaddress.ip_network(r) for r in value['permitted_ip']) and not any(ip in ipaddress.ip_network(r) for r in value['excluded_ip'] if ip.version==ipaddress.ip_network(r).version)
