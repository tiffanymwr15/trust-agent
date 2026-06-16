import yaml
import os
import re
from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None


def _business_hours():
    """Load the business-hours window (start, end, timezone) from
    context/policies.yaml. Falls back to 08:00-18:00 UTC if unset."""
    try:
        cfg = load_policies().get('business_hours', {}) or {}
    except Exception:
        cfg = {}
    return (
        int(cfg.get('start', 8)),
        int(cfg.get('end', 18)),
        str(cfg.get('timezone', 'UTC')),
    )


def _local_hour(timestamp: str, tz_name: str):
    """Parse an ISO-8601 timestamp (UTC, possibly 'Z'/fractional seconds)
    and return (hour_of_day, tz_abbrev) in the configured timezone.
    Returns (None, None) if it can't be parsed."""
    if not timestamp:
        return None, None
    ts = timestamp.strip().replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        m = re.match(r'(.*\.\d{6})\d*([+-]\d{2}:\d{2})?$', ts)
        if not m:
            return None, None
        try:
            dt = datetime.fromisoformat(m.group(1) + (m.group(2) or '+00:00'))
        except ValueError:
            return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if tz_name and tz_name.upper() != 'UTC' and ZoneInfo is not None:
        try:
            local = dt.astimezone(ZoneInfo(tz_name))
            return local.hour, local.tzname()
        except Exception:
            pass  # unknown tz / no tzdata -> fall back to UTC
    return dt.astimezone(timezone.utc).hour, 'UTC'


def load_policies():
    config_path = os.path.join(
        os.path.dirname(__file__), '..', 'context', 'policies.yaml'
    )
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


PII_PATTERNS = {
    'social_security_number': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card_number': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'email_address': r'(?<!:)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'phone_number': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
}

CREDENTIAL_PATTERNS = {
    'api_key': r'(sk-[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})',
    'password': r'(password|passwd|pwd)\s*[:=]\s*\S+',
    'connection_string': r'(postgresql|mysql|mongodb|redis):\/\/[^\s]+',
    'secret_key': r'(secret|token|bearer)\s*[:=]\s*\S+',
    'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
}

# Aperture wraps session identity into the `prompt` field as metadata, e.g.:
#   "Session for user user@example.com: 4 request(s), models: ..."
# This is gateway-generated identity context, NOT user-authored prompt content,
# so PII scanning must strip it first to avoid false-positive email matches.
APERTURE_META_PREFIX = re.compile(
    r'^Session for user\s+\S+:\s*\d+\s+request\(s\),\s*models:.*$',
    re.IGNORECASE | re.MULTILINE,
)


def strip_session_metadata(prompt: str) -> str:
    """Remove Aperture's session-identity metadata so PII checks only see
    actual user-authored prompt content."""
    return APERTURE_META_PREFIX.sub('', prompt).strip()


def check_event(event: dict) -> list:
    violations = []
    prompt = strip_session_metadata(event.get('prompt', ''))
    output = event.get('output', '')

    for pattern_name, regex in PII_PATTERNS.items():
        if re.search(regex, prompt, re.IGNORECASE):
            violations.append({
                'policy_id': 'PII_IN_PROMPT',
                'pattern_matched': pattern_name,
                'location': 'prompt',
                'severity': 'high',
            })

    for pattern_name, regex in CREDENTIAL_PATTERNS.items():
        if re.search(regex, prompt, re.IGNORECASE):
            violations.append({
                'policy_id': 'CREDENTIALS_IN_PROMPT',
                'pattern_matched': pattern_name,
                'location': 'prompt',
                'severity': 'critical',
            })
        if re.search(regex, output, re.IGNORECASE):
            violations.append({
                'policy_id': 'CREDENTIALS_IN_OUTPUT',
                'pattern_matched': pattern_name,
                'location': 'output',
                'severity': 'critical',
            })

    start_hour, end_hour, tz_name = _business_hours()
    hour, tz_abbrev = _local_hour(event.get('timestamp', ''), tz_name)

    if hour is not None and (hour < start_hour or hour >= end_hour):
        violations.append({
            'policy_id': 'OFF_HOURS_USAGE',
            'severity': 'low',
            'detail': f'Usage at hour {hour}:00 {tz_abbrev}',
        })

    token_count = event.get('token_count', 0)
    if token_count > 1000:
        violations.append({
            'policy_id': 'BULK_DATA_EXTRACTION',
            'severity': 'high',
            'detail': f'Large response: {token_count} tokens',
        })

    return violations


if __name__ == '__main__':
    test_event = {
        'prompt': 'Debug this: postgresql://admin:secret123@db:5432/prod',
        'output': 'The connection string looks correct...',
        'timestamp': '2026-04-13T03:00:00Z',
        'token_count': 150,
    }
    results = check_event(test_event)
    for v in results:
        print(
            f"[{v['severity'].upper()}] {v['policy_id']}: "
            f"{v.get('pattern_matched', v.get('detail', ''))}"
        )
