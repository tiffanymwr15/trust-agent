import yaml
import os
import re


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


def check_event(event: dict) -> list:
    violations = []
    prompt = event.get('prompt', '')
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

    hour = None
    timestamp = event.get('timestamp', '')
    if timestamp:
        try:
            hour = int(timestamp[11:13])
        except (ValueError, IndexError):
            pass

    if hour is not None and (hour < 8 or hour >= 18):
        violations.append({
            'policy_id': 'OFF_HOURS_USAGE',
            'severity': 'low',
            'detail': f'Usage at hour {hour}:00 UTC',
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
