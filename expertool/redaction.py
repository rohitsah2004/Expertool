"""Layered secret redaction. Keys/patterns are primary; bounded value recall is best-effort."""
from collections import OrderedDict
import json
import math
import re
import threading
from urllib.parse import parse_qsl,quote,urlencode,urlsplit,urlunsplit

REDACTED='[REDACTED]'
_LOCK=threading.RLock()
_SECRETS=OrderedDict()
MAX_SECRETS=128
MAX_SECRET_BYTES=4096
MAX_REGISTRY_BYTES=65536
_SECRET_PATTERN=None
_SECRET_SNAPSHOT=()
_SECRET_INITIALS=frozenset()
_NORMALIZE=re.compile(r'[-_.\s]+')
_CAMEL=re.compile(r'([a-z0-9])([A-Z])')
_JSON_LITERAL=re.compile(r'(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)')
_SENSITIVE_PARTS=('authorization','cookie','password','passwd','secret','token','apikey','accesskey','credential','session','signature','csrf','xsrf','authkey','privatekey','jwt','bearer')
_EXACT_SENSITIVE={'auth','xauth','otp','pin','sid','sig'}
_PUBLIC_KEYS={'tokentype','tokenizer'}
_BOOLEAN_KEYS={'csrfrequired','xsrfrequired'}
_PARAM_KEYS={'code','sig','signature','xamzsignature','xamzcredential','xamzsecuritytoken','auth','authorization','idtoken','jwt','clientsecret','apikey','accesskey','secret','password','passwd','otp','pin','session','sid','key'}
_COMMON={'true','false','null','none','undefined','yes','no','on','off','notauthenticated','unauthenticated','notavailable','notconfigured'}
_LOCALE=re.compile(r'[a-zA-Z]{2,3}(?:[-_][a-zA-Z0-9]{2,8})+')
_BOUNDARY=r'[\w-]'
_LABEL=re.compile(r'(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9_.-]*(?:[ \t]+(?:key|token|secret))?)([ \t]*[:=][ \t]*)',re.I)
_BEARER=re.compile(r'\bBearer[ \t]+[A-Za-z0-9._~+/=-]+',re.I)
_URL=re.compile(r'https?://[^\s<>"\']+',re.I)
PATTERNS=[
    re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})\b'),
    re.compile(r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
]


def normalize_key(key):
    return _NORMALIZE.sub('',_CAMEL.sub(r'\1 \2',str(key))).lower()


def is_sensitive_key(key,value=None):
    name=normalize_key(key)
    if name in _PUBLIC_KEYS or (name in _BOOLEAN_KEYS and type(value) is bool):return False
    return name in _EXACT_SENSITIVE or any(part in name for part in _SENSITIVE_PARTS)


def _eligible(value):
    if not isinstance(value,str):return False
    value=value.strip()
    if len(value)<12 or len(value)>MAX_SECRET_BYTES or len(value.encode())>MAX_SECRET_BYTES or value.lower() in _COMMON or _LOCALE.fullmatch(value):return False
    if value.isdigit() and len(value.lstrip('0'))<=6:return False
    return not any(ord(c)<32 for c in value)


def _high_entropy(value):
    if len(value)<20:return False
    # Cookie names can be opaque: require a diverse, non-word-like value.
    counts={c:value.count(c) for c in set(value)}
    entropy=-sum((n/len(value))*math.log2(n/len(value)) for n in counts.values())
    classes=sum(bool(re.search(p,value)) for p in (r'[a-z]',r'[A-Z]',r'[0-9]',r'[^A-Za-z0-9]'))
    return entropy>=3.5 and classes>=2


def register_credentials(headers):
    """Recall only plausible credential values; never arbitrary cookie literals."""
    values=[]
    for key,value in (headers or {}).items():
        if not isinstance(value,str):continue
        name=normalize_key(key)
        if name in {'cookie','setcookie'}:
            pieces=value.split(';') if name=='cookie' else value.split(';',1)[:1]
            for piece in pieces:
                cookie,separator,raw=piece.strip().partition('=')
                candidate=raw.strip().strip('"')
                sensitive=is_sensitive_key(cookie) or normalize_key(cookie).endswith(('sid','sessid')) or normalize_key(cookie).startswith('sess')
                if separator and _eligible(candidate) and (sensitive or _high_entropy(candidate)):values.append(candidate)
        elif is_sensitive_key(key):
            candidate=value.strip()
            if name.endswith('authorization'):
                parts=candidate.split(None,1)
                if len(parts)==2 and parts[0].lower() in {'basic','bearer'}:candidate=parts[1]
            if _eligible(candidate):values.append(candidate)
    with _LOCK:
        for value in values:
            _SECRETS[value]=len(value.encode());_SECRETS.move_to_end(value)
        while len(_SECRETS)>MAX_SECRETS or sum(_SECRETS.values())>MAX_REGISTRY_BYTES:_SECRETS.popitem(last=False)


def _registered(text):
    global _SECRET_PATTERN,_SECRET_SNAPSHOT,_SECRET_INITIALS
    with _LOCK:
        snapshot=tuple(sorted(_SECRETS))
        if snapshot!=_SECRET_SNAPSHOT:
            _SECRET_SNAPSHOT=snapshot
            _SECRET_INITIALS=frozenset(value[0] for value in snapshot)
            _SECRET_PATTERN=re.compile(r'(?<!'+_BOUNDARY+r')(?:'+'|'.join(re.escape(v) for v in sorted(snapshot,key=len,reverse=True))+r')(?!'+_BOUNDARY+r')') if snapshot else None
        pattern=_SECRET_PATTERN;initials=_SECRET_INITIALS
    if not pattern or not any(char in text for char in initials):return text
    hits=[]
    def replace(match):hits.append(match[0]);return REDACTED
    result=pattern.sub(replace,text)
    if hits:
        with _LOCK:
            for value in hits:
                if value in _SECRETS:_SECRETS.move_to_end(value)
    return result


def _parameters(text,oauth_code=False):
    try:items=parse_qsl(text,keep_blank_values=True,max_num_fields=2048)
    except ValueError:return 'redacted=%5BREDACTED%5D'
    oauth=oauth_code or any(normalize_key(key)=='code' for key,_ in items)
    result=[];changed=False
    for key,value in items:
        name=normalize_key(key)
        sensitive=name in _PARAM_KEYS or is_sensitive_key(key,value) or (name=='state' and oauth)
        cleaned=REDACTED if sensitive else _plain(value)
        changed=changed or cleaned!=value
        result.append((key,cleaned))
    return urlencode(result) if changed or REDACTED in text else text


def _url(value):
    try:
        parsed=urlsplit(value)
        authority=parsed.netloc
        if '@' in authority:authority='%5BREDACTED%5D@'+authority.rsplit('@',1)[1]
        try:oauth=any(normalize_key(key)=='code' for key,_ in parse_qsl(parsed.query+'&'+parsed.fragment,keep_blank_values=True,max_num_fields=2048))
        except ValueError:oauth=True
        query=_parameters(parsed.query,oauth_code=oauth) if parsed.query else ''
        # OAuth responses sometimes use fragment parameters rather than query.
        fragment=_parameters(parsed.fragment,oauth_code=oauth) if '=' in parsed.fragment else _plain(parsed.fragment)
        path=_plain(parsed.path).replace(REDACTED,quote(REDACTED,safe=''))
        fragment=fragment.replace(REDACTED,quote(REDACTED,safe=''))
        return urlunsplit((parsed.scheme,authority,path,query,fragment))
    except ValueError:return '[REDACTED URL]'


def _assignments(text,colon_only=False):
    output=[];end=0
    for match in _LABEL.finditer(text):
        if match.start()<end or not is_sensitive_key(match[1]) or (colon_only and ':' not in match[2]):continue
        start=match.end();stop=start
        if ':' in match[2]:
            # Header/evidence field: mask the whole value, not just 'Basic'.
            stop=text.find('\n',start)
            if stop<0:stop=len(text)
            if stop>start and text[stop-1]=='\r':stop-=1
        elif start<len(text) and text[start] in {'"',"'"}:
            quote=text[start];close=text.find(quote,start+1)
            stop=len(text) if close<0 else close+1
        else:
            while stop<len(text) and text[stop] not in ' \t\r\n,;&<>}':stop+=1
        output.extend((text[end:start],REDACTED));end=stop
    return ''.join(output)+text[end:] if output else text


def _plain(text):
    # Fast syntax/prefix gates avoid repeated regex scans of large benign bodies.
    if 'bearer' in text.lower():
        text=_BEARER.sub('Bearer '+REDACTED,text)
    if any(prefix in text for prefix in ('ghp_','gho_','ghu_','ghs_','ghr_','github_pat_','AKIA','sk_live_','xox')):
        text=PATTERNS[0].sub(REDACTED,text)
    if 'eyJ' in text:text=PATTERNS[1].sub(REDACTED,text)
    return _registered(text)


def redact_text(text,*,content_type=None,_depth=0,_string_value=False):
    """Preserve structured JSON/JSONL; redact only string values or secret fields."""
    stripped=text.lstrip()
    if not _string_value and stripped and stripped[0] in 'tfn-0123456789' and _JSON_LITERAL.fullmatch(stripped.rstrip()):return text
    if _depth<20 and stripped.startswith(('{','[','"')):
        try:return json.dumps(_sanitize(json.loads(text),_depth+1),ensure_ascii=False)
        except (ValueError,TypeError,RecursionError):pass
    if _depth<20 and '\n' in text and stripped and stripped[0] in '{[\"tfn-0123456789':
        lines=text.splitlines();parsed=[]
        try:
            for line in lines:
                if line.strip():parsed.append(json.dumps(_sanitize(json.loads(line),_depth+1),ensure_ascii=False))
                else:parsed.append(line)
            return '\n'.join(parsed)
        except (ValueError,TypeError,RecursionError):pass
    media=(content_type or '').split(';',1)[0].lower()
    if media=='application/x-www-form-urlencoded':return _parameters(text)
    # Mask sensitive header/evidence fields before considering embedded URLs.
    if ':' in text:text=_assignments(text,colon_only=True)
    if '://' in text:
        output=[];end=0
        for match in _URL.finditer(text):
            output.extend((_non_url(text[end:match.start()]),_url(match[0])));end=match.end()
        if output:return ''.join(output)+_non_url(text[end:])
    return _non_url(text)


def _non_url(text):
    if text.startswith(('?','#')) and '=' in text and '\n' not in text:return text[0]+_parameters(text[1:])
    if '=' in text and '\n' not in text and ('&' in text or re.fullmatch(r'[^\s=&]+=[^\s]*',text)):
        return _parameters(text)
    if ':' in text or '=' in text:text=_assignments(text)
    return _plain(text)


def _headers(value,depth):
    if isinstance(value,dict):return _sanitize(value,depth)
    if isinstance(value,(list,tuple)):
        result=[]
        for pair in value:
            if isinstance(pair,(list,tuple)) and len(pair)==2 and isinstance(pair[0],str):
                key,raw=pair;result.append([key,REDACTED if is_sensitive_key(key,raw) else _sanitize(raw,depth+1)])
            else:result.append(_sanitize(pair,depth+1))
        return result
    return _sanitize(value,depth)


def _sanitize(value,depth=0):
    if depth>40:return REDACTED
    if isinstance(value,dict):
        headers=value.get('headers',{})
        pairs=headers.items() if isinstance(headers,dict) else headers if isinstance(headers,(list,tuple)) else []
        content_type=next((pair[1] for pair in pairs if isinstance(pair,(list,tuple)) and len(pair)==2 and normalize_key(pair[0])=='contenttype' and isinstance(pair[1],str)),None)
        result={}
        for key,item in value.items():
            if is_sensitive_key(key,item):result[str(key)]=REDACTED
            elif normalize_key(key)=='headers':result[str(key)]=_headers(item,depth+1)
            elif normalize_key(key)=='body' and isinstance(item,str):result[str(key)]=redact_text(item,content_type=content_type,_depth=depth+1)
            else:result[str(key)]=_sanitize(item,depth+1)
        return result
    if isinstance(value,(list,tuple)):return [_sanitize(v,depth+1) for v in value]
    if isinstance(value,str):return redact_text(value,_depth=depth+1,_string_value=True)
    return value


def sanitize(value):return _sanitize(value)


def sanitize_output(content):
    """Redact JSON/JSONL string values and fields before serializing valid framing."""
    try:return json.dumps(sanitize(json.loads(content)),ensure_ascii=False)
    except (ValueError,TypeError,RecursionError):
        lines=[]
        for line in content.splitlines():
            try:lines.append(json.dumps(sanitize(json.loads(line)),ensure_ascii=False))
            except (ValueError,TypeError,RecursionError):lines.append(redact_text(line))
        return '\n'.join(lines)
