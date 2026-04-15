"""
Run the full trust-agent pipeline against a batch of AI usage events.

Usage:
    python run_batch.py <events.json> [--report-type daily|weekly|monthly]
    python run_batch.py sample_data/events.json

Outputs a per-event breakdown and saves a JSON report under reports/.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))

from policy_engine import check_event
from compliance_mapper import enrich_violations
from report_builder import generate_report, save_report


def load_events(path: str) -> list:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def run(events_path: str, report_type: str = 'daily') -> dict:
    events = load_events(events_path)
    all_violations = []

    print('=' * 70)
    print(f'TRUST-AGENT PIPELINE - {len(events)} events')
    print('=' * 70)

    for e in events:
        eid = e.get('event_id', '?')
        user = e.get('user', '?')
        team = e.get('team', '?')
        violations = check_event(e)
        enriched = enrich_violations(violations) if violations else []
        for v in enriched:
            v['event_id'] = eid
            all_violations.append(v)

        print(f'\n[{eid}] {user} ({team})')
        if not enriched:
            print('  no violations')
            continue
        for v in enriched:
            detail = v.get('pattern_matched') or v.get('detail', '')
            frameworks = ', '.join(v.get('compliance', {}).keys()) or 'none'
            print(f"  [{v['severity'].upper()}] {v['policy_id']} ({detail})")
            print(f'    frameworks: {frameworks}')

    report = generate_report(events, all_violations, report_type)
    path = save_report(report, 'reports')

    print()
    print('=' * 70)
    print(f'{report_type.upper()} REPORT')
    print('=' * 70)
    print(json.dumps(report['summary'], indent=2))
    print()
    print('Recommendations:')
    for rec in report['recommendations']:
        print(f'  - {rec}')
    print()
    print(f'Saved: {path}')

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description='Run trust-agent pipeline on a batch of events.')
    parser.add_argument('events', help='Path to a JSON file containing a list of events')
    parser.add_argument(
        '--report-type',
        choices=['daily', 'weekly', 'monthly'],
        default='daily',
        help='Report type to generate (default: daily)',
    )
    args = parser.parse_args()
    run(args.events, args.report_type)


if __name__ == '__main__':
    main()
