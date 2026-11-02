"""Data-only readers for saved tool output; never launch the tools."""
import json
from urllib.parse import urlsplit

from .workspace import normalize_url

FORMATS = ('normalized', 'headers', 'subfinder', 'subfinder-json', 'httpx', 'nuclei')


def text_field(record, key, required=False):
    value = record.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f'{key} must be a nonempty string' if required else f'{key} must be a string')
    return value


def selected(record, fields):
    """Keep only documented metadata, not raw bodies, headers, requests or secrets."""
    return {key: record[key] for key in fields if key in record}


def subfinder(record):
    from .scope import hostname
    host = text_field(record, 'host', required=True)
    if '://' in host or '/' in host:
        raise ValueError('Subfinder host must be a bare hostname')
    host = hostname(host)
    metadata = selected(record, ('input', 'source', 'sources', 'ip', 'wildcard_certificate'))
    return {'url': 'dns://' + host, 'metadata': metadata}


def httpx(record):
    url = text_field(record, 'url', required=True)
    normalize_url(url)
    if 'failed' in record and not isinstance(record['failed'], bool):
        raise ValueError('failed must be boolean')
    status = record.get('status_code')
    if status is not None and (type(status) is not int or not 0 <= status <= 599):
        raise ValueError('status_code must be an integer between 0 and 599')
    # A failed probe is useful evidence, but does not mean a service is live.
    return {'url': url, 'metadata': selected(record, (
        'timestamp', 'status_code', 'title', 'webserver', 'tech', 'content_type',
        'content_length', 'failed', 'error', 'final_url', 'host_ip', 'hash'))}


def nuclei(record):
    if record.get('type') != 'http':
        raise ValueError('Only HTTP Nuclei results are supported in this version')
    status = record.get('matcher-status', True)
    if not isinstance(status, bool):
        raise ValueError('matcher-status must be boolean')
    info = record.get('info')
    if not isinstance(info, dict):
        raise ValueError('info must be an object')
    template = text_field(record, 'template-id', required=True)
    title = text_field(info, 'name', required=True)
    severity = text_field(info, 'severity', required=True).lower()
    if severity not in {'info', 'low', 'medium', 'high', 'critical', 'unknown'}:
        raise ValueError('Unsupported Nuclei severity')
    url = text_field(record, 'matched-at') or text_field(record, 'url') or text_field(record, 'host', required=True)
    if urlsplit(url).scheme not in {'http', 'https'}:
        raise ValueError('Nuclei HTTP result needs an explicit HTTP(S) URL')
    normalize_url(url)
    matcher = text_field(record, 'matcher-name') or ''
    extractor = text_field(record, 'extractor-name') or ''
    # JSON identity avoids delimiter collisions between template and matcher names.
    check_id = 'nuclei:' + json.dumps([template, matcher, extractor], separators=(',', ':'))
    metadata = selected(record, ('template-id', 'matcher-name', 'extractor-name', 'timestamp', 'matcher-status', 'type'))
    metadata['reported_severity'] = severity
    evidence = {'tool': 'nuclei', **metadata,
                'note': 'Imported scanner match; not independently verified. Raw request, response, extracted values and curl commands omitted.'}
    findings = []
    if status and not record.get('error'):
        findings.append({'check_id': check_id, 'title': title,
                         'severity': 'info' if severity == 'unknown' else severity,
                         'evidence': json.dumps(evidence, indent=2)})
    return {'url': url, 'metadata': metadata, 'findings': findings}


def parse_output(content, format_name):
    if format_name not in FORMATS:
        raise ValueError(f'Unsupported format: {format_name}')
    records = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            if format_name == 'subfinder':
                record = subfinder({'host': line.strip()})
            else:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError('Expected a JSON object')
                if format_name == 'subfinder-json':
                    record = subfinder(record)
                elif format_name == 'httpx':
                    record = httpx(record)
                elif format_name == 'nuclei':
                    record = nuclei(record)
            records.append(record)
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError(f'{format_name} line {line_number}: {error}') from error
    if format_name == 'headers':
        from .workspace import inspect_headers
        return inspect_headers(records)
    return records
