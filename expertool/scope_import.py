"""Offline scope conversion. Imported scope is a review draft, never scan permission."""
import hashlib
import json

from .scope import parse_asset_rule


def convert_scope(document, provider='normalized', exclusions=None):
    if provider not in {'hackerone','normalized'}:
        raise ValueError('Supported formats: hackerone, normalized')
    if not isinstance(document,dict):
        raise ValueError('Scope export must be an object')
    blockers=[]
    instructions=[]
    rows=[]
    if provider=='hackerone':
        data=document.get('data')
        if not isinstance(data,list):
            raise ValueError('Expected HackerOne structured-scopes data array')
        if document.get('links',{}).get('next'):
            blockers.append('Export has another page; include every page before review')
        for item in data:
            if not isinstance(item,dict) or item.get('type')!='structured-scope' or not isinstance(item.get('attributes'),dict):
                raise ValueError('Expected structured-scope entries')
            attr=item['attributes']
            eligible=attr.get('eligible_for_submission')
            if type(eligible) is not bool:
                raise ValueError('eligible_for_submission must be explicit boolean')
            rows.append({'identifier':attr.get('asset_identifier'),'in_scope':eligible,
                         'asset_type':attr.get('asset_type'),'instructions':attr.get('instruction')})
        if exclusions is None:
            blockers.append('Separate scope-exclusions export not provided')
        else:
            if not isinstance(exclusions,dict) or not isinstance(exclusions.get('data'),list):
                raise ValueError('Expected HackerOne scope-exclusions data array')
            if exclusions.get('links',{}).get('next'):
                blockers.append('Scope exclusions export has another page')
            for item in exclusions['data']:
                attr=item.get('attributes',{}) if isinstance(item,dict) else {}
                if not isinstance(attr,dict):
                    raise ValueError('Invalid exclusion entry')
                instructions.append({'category':attr.get('category'),'details':attr.get('details')})
    else:
        if document.get('provider') not in {'hackerone','bugcrowd','intigriti','manual'}:
            raise ValueError('Normalized export requires a known provider label')
        rows=document.get('assets')
        if not isinstance(rows,list):
            raise ValueError('Normalized export requires assets array')
        if document.get('complete') is not True:
            blockers.append('Export completeness has not been explicitly confirmed')
        instructions.append({'rules':document.get('instructions','Review the full current program policy')})
    included,excluded,hosts,excluded_hosts=[],[],[],[]
    for index,row in enumerate(rows,1):
        if not isinstance(row,dict) or type(row.get('in_scope')) is not bool:
            raise ValueError(f'Asset {index} requires explicit in_scope boolean')
        value=row.get('identifier')
        if row.get('instructions'):
            instructions.append({'asset':value,'instructions':row['instructions']})
        if provider=='hackerone' and row.get('asset_type') not in {'URL','WILDCARD','DOMAIN','IP_ADDRESS','IP','CIDR'}:
            blockers.append(f'Asset {index}: unsupported asset type {row.get("asset_type")}')
            continue
        try:
            parsed=parse_asset_rule(value,not row['in_scope'])
        except (ValueError,TypeError) as error:
            blockers.append(f'Asset {index}: {error}')
            continue
        if row['in_scope']:
            included.append(value)
            hosts.append(parsed['host'])
        else:
            excluded.append(value)
            if parsed['kind']=='host':
                excluded_hosts.append(parsed['host'])
    if not included:
        blockers.append('No supported in-scope web/network assets')
    policy={'authorized':False,'include':list(dict.fromkeys(hosts)), 'exclude':list(dict.fromkeys(excluded_hosts)),
        'asset_scope':{'include':list(dict.fromkeys(included)),'exclude':list(dict.fromkeys(excluded))},
        'allowed_modes':['passive','manual'], 'automation':{'allowed':False,'tools':[]},
        'scope_review':{'complete':False,'blockers':blockers,'instructions':instructions,
            'source':provider if provider!='normalized' else document['provider'],
            'source_sha256':hashlib.sha256(json.dumps(document,sort_keys=True).encode()).hexdigest(),
            'exclusions_sha256':hashlib.sha256(json.dumps(exclusions,sort_keys=True).encode()).hexdigest() if exclusions is not None else None,
            'note':'Review full current program policy, exclusions, automated-tool permissions and rates before enabling. Submission/bounty eligibility is not scanning authorization.'}}
    return policy
