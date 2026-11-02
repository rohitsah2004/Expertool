"""Manual interception permission is separate from automated scanner permission."""
from datetime import datetime
from .scope import validate_program
from .execution import scan_settings

READ_ONLY={'GET','HEAD','OPTIONS'}
STATE_CHANGING={'POST','PUT','PATCH','DELETE'}

def interception_settings(policy):
    validate_program(policy)
    raw=policy.get('interception',{})
    if not isinstance(raw,dict) or set(raw)-{'enabled','state_changing','passthrough','websocket_capture','raw_capture'}:
        raise ValueError('Invalid interception settings')
    if raw.get('enabled') is not True or 'manual' not in policy.get('allowed_modes',[]):
        raise ValueError('Manual interception requires explicit opt-in and manual mode')
    for feature in ('websocket_capture','raw_capture'):
        if raw.get(feature,False) is not False:raise ValueError('Unsupported interception feature: '+feature)
    state=raw.get('state_changing',{'enabled':False})
    if not isinstance(state,dict) or set(state)-{'enabled','approved_by','approved_at'} or type(state.get('enabled')) is not bool:
        raise ValueError('Invalid state-changing method approval')
    if state['enabled']:
        if not isinstance(state.get('approved_by'),str) or not state['approved_by'].strip() or len(state['approved_by'])>200:
            raise ValueError('State-changing approval requires approved_by')
        try:
            date=datetime.fromisoformat(state['approved_at'].replace('Z','+00:00'))
            if date.tzinfo is None:raise ValueError('Timezone required')
        except (KeyError,AttributeError,TypeError,ValueError):raise ValueError('State-changing approval requires a timezone-aware approved_at') from None
    from .passthrough import controls
    passthrough=controls(policy)
    return {'state_changing':state['enabled'],'passthrough':passthrough}

def manual_settings(policy):
    interception_settings(policy)
    return scan_settings(policy)

def method_allowed(policy,method):
    settings=interception_settings(policy)
    return method in READ_ONLY or (method in STATE_CHANGING and settings['state_changing'])
