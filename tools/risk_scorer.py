import yaml
import os


def load_thresholds():
    config_path = os.path.join(
        os.path.dirname(__file__), '..', 'context', 'risk_thresholds.yaml'
    )
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def score_event(event: dict, analysis: dict) -> dict:
    config = load_thresholds()
    factors = config['scoring_factors']

    data_score = factors['data_sensitivity']['values'].get(
        analysis.get('data_sensitivity', 'public'), 10
    )
    role_score = factors['user_role']['values'].get(
        event.get('user_role', 'standard_user'), 20
    )
    freq_score = factors['frequency']['values'].get(
        analysis.get('frequency', 'first_occurrence'), 30
    )
    policy_score = factors['policy_relevance']['values'].get(
        analysis.get('policy_relevance', 'informational'), 10
    )

    total = (
        data_score * factors['data_sensitivity']['weight']
        + role_score * factors['user_role']['weight']
        + freq_score * factors['frequency']['weight']
        + policy_score * factors['policy_relevance']['weight']
    )

    severity = 'info'
    for level in ['critical', 'high', 'medium', 'low', 'info']:
        if total >= config['risk_levels'][level]['min_score']:
            severity = level
            break

    return {
        'score': round(total, 2),
        'severity': severity,
        'alert_type': config['risk_levels'][severity]['alert'],
        'factors': {
            'data_sensitivity': {
                'value': analysis.get('data_sensitivity', 'public'),
                'score': data_score,
            },
            'user_role': {
                'value': event.get('user_role', 'standard_user'),
                'score': role_score,
            },
            'frequency': {
                'value': analysis.get('frequency', 'first_occurrence'),
                'score': freq_score,
            },
            'policy_relevance': {
                'value': analysis.get('policy_relevance', 'informational'),
                'score': policy_score,
            },
        },
    }


if __name__ == '__main__':
    test_event = {'user_role': 'admin'}
    test_analysis = {
        'data_sensitivity': 'credentials',
        'frequency': 'first_occurrence',
        'policy_relevance': 'direct_violation',
    }
    result = score_event(test_event, test_analysis)
    print(f"Score: {result['score']}, Severity: {result['severity']}")
