import yaml
import os


def load_compliance_maps():
    config_path = os.path.join(
        os.path.dirname(__file__), '..', 'context', 'compliance_maps.yaml'
    )
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def map_violation(policy_id: str) -> dict:
    maps = load_compliance_maps()
    result = {}

    for framework_key, framework in maps['frameworks'].items():
        if policy_id in framework.get('mappings', {}):
            mapping = framework['mappings'][policy_id]
            result[framework_key] = {
                'framework_name': framework['name'],
                'references': (
                    mapping.get('articles')
                    or mapping.get('controls')
                    or mapping.get('functions', [])
                ),
                'description': mapping.get('description', ''),
            }

    return result


def enrich_violations(violations: list) -> list:
    enriched = []
    for v in violations:
        compliance = map_violation(v['policy_id'])
        enriched.append({**v, 'compliance': compliance})
    return enriched


if __name__ == '__main__':
    test_violations = [
        {'policy_id': 'PII_IN_PROMPT', 'severity': 'high'},
        {'policy_id': 'CREDENTIALS_IN_PROMPT', 'severity': 'critical'},
    ]
    results = enrich_violations(test_violations)
    for r in results:
        print(f"\n[{r['severity'].upper()}] {r['policy_id']}")
        for fw, details in r.get('compliance', {}).items():
            refs = ', '.join(details['references'])
            print(f"  {details['framework_name']}: {refs}")
