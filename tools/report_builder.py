import json
import os
from datetime import datetime, timezone


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _utcnow_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')


def generate_report(events: list, violations: list, report_type: str = 'daily') -> dict:
    now = _utcnow_iso()

    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    policy_counts = {}
    team_counts = {}

    for v in violations:
        sev = v.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        pid = v.get('policy_id', 'unknown')
        policy_counts[pid] = policy_counts.get(pid, 0) + 1

    for e in events:
        team = e.get('team', 'unknown')
        team_counts[team] = team_counts.get(team, 0) + 1

    report = {
        'report_type': report_type,
        'generated_at': now,
        'period': report_type,
        'summary': {
            'total_events_analyzed': len(events),
            'total_violations': len(violations),
            'severity_breakdown': severity_counts,
            'top_violations': dict(
                sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)
            ),
            'team_activity': team_counts,
        },
        'critical_findings': [v for v in violations if v.get('severity') == 'critical'],
        'high_findings': [v for v in violations if v.get('severity') == 'high'],
        'recommendations': [],
    }

    if severity_counts['critical'] > 0:
        report['recommendations'].append(
            'IMMEDIATE: Review and rotate all exposed credentials'
        )
    if severity_counts['high'] > 0:
        report['recommendations'].append(
            'HIGH PRIORITY: Implement data masking for AI prompts containing PII'
        )
    if policy_counts.get('BULK_DATA_EXTRACTION', 0) > 0:
        report['recommendations'].append(
            'Review data extraction patterns and enforce DLP controls'
        )
    if policy_counts.get('OFF_HOURS_USAGE', 0) > 0:
        report['recommendations'].append(
            'Audit off-hours AI usage for unauthorized access'
        )

    return report


def save_report(report: dict, output_dir: str = 'reports') -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{report['report_type']}_{_utcnow_stamp()}.json"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)
    return filepath


if __name__ == '__main__':
    test_events = [{'team': 'engineering'}, {'team': 'hr'}]
    test_violations = [
        {'policy_id': 'CREDENTIALS_IN_PROMPT', 'severity': 'critical'},
        {'policy_id': 'PII_IN_PROMPT', 'severity': 'high'},
    ]
    report = generate_report(test_events, test_violations)
    print(json.dumps(report, indent=2))
