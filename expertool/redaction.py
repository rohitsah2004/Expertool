"""Conservative evidence sanitization. Credential values remain in process memory only."""
import re
import threading
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_LOCK = threading.Lock()
_SECRETS = set()
SENSITIVE = re.compile(r'(?i)^(?:authorization|proxy.authorization|cookie|set.cookie|password|passwd|secret|access.token|refresh.token|api.key|token|credential|session.id)$')
PATTERNS = [
    re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})\b'),
    re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
]


def register_credentials(headers):
    values = []
    for key, value in (headers or {}).items():
        if not isinstance(value, str):
            continue
        values.append(value)
        if key.lower() in {'authorization', 'proxy-authorization'}:
            values.append(value.split(' ', 1)[-1])
        if key.lower() == 'cookie':
            values.extend(p.split('=', 1)[-1].strip() for p in value.split(';'))
    with _LOCK:
        _SECRETS.update(v for v in values if len(v) >= 4)


def redact_text(text):
    text=re.sub(r'(?i)(https?://)[^/@\s"\']+@',r'\1[REDACTED]@',text)
    with _LOCK:
        secrets = sorted(_SECRETS, key=len, reverse=True)
    for value in secrets:
        text = text.replace(value, '[REDACTED]')
    for pattern in PATTERNS:
        text = pattern.sub('[REDACTED]', text)
    text = re.sub(r'(?im)\b((?:proxy-)?authorization\s*[:=]\s*)([^\r\n]+)', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'(?im)\b((?:set-)?cookie\s*:\s*)([^\r\n]+)', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)([?&](?:token|access_token|refresh_token|api_key|key|password|secret|session)=)[^&#\s"\']+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)\b((?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*)["\']?[^\s,"\';}]+', r'\1[REDACTED]', text)
    return text


def sanitize(value):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SENSITIVE.fullmatch(str(k)) else sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def sanitize_output(content):
    """Redact parsed JSON/JSONL values without corrupting their framing."""
    try:
        return json.dumps(sanitize(json.loads(content)))
    except (ValueError,TypeError):
        lines=[]
        for line in content.splitlines():
            try:lines.append(json.dumps(sanitize(json.loads(line))))
            except (ValueError,TypeError):lines.append(sanitize(line))
        return '\n'.join(lines)
