---
name: classify-risk
description: Score and classify the severity of an analyzed AI usage event using weighted factors (data sensitivity, policy relevance, frequency, user role). Returns a numeric score and severity level from Critical to Info. Use after analyze-risk has produced an analysis.
user-invocable: true
---

# Classify Risk

Turn an event + analysis into a numeric risk score and severity label.

## When to use

After `analyze-risk` has produced an analysis, or any time you have an event plus its sensitivity/policy assessment and need a severity rating.

## Input

- `event` — the original event (needs `user_role` at minimum)
- `analysis` — the output of `analyze-risk` (needs `data_sensitivity`, `policy_relevance`, optionally `frequency`)

## Scoring model

Weighted factor sum, 0–100 scale:

| Factor            | Weight | Values                                                                                       |
|-------------------|--------|----------------------------------------------------------------------------------------------|
| data_sensitivity  | 35%    | credentials=100, pii=80, proprietary=60, internal=30, public=10                              |
| policy_relevance  | 30%    | direct_violation=100, potential_violation=70, best_practice=40, informational=10             |
| frequency         | 20%    | repeat_offender=100, recurring=70, occasional=40, first_occurrence=30                        |
| user_role         | 15%    | admin=80, privileged=60, standard_user=20, external=90                                       |

`total = 0.35*data + 0.30*policy + 0.20*freq + 0.15*role`

## Severity thresholds

| Severity | Min score | Alert type      |
|----------|-----------|-----------------|
| critical | 90        | immediate       |
| high     | 70        | within_1_hour   |
| medium   | 40        | daily_summary   |
| low      | 20        | weekly_report   |
| info     | 0         | monthly_report  |

## Instructions

1. Pull each factor value from the event/analysis. Use defaults for missing fields (`public`, `informational`, `first_occurrence`, `standard_user`).
2. Compute the weighted total.
3. Walk severity thresholds top-down; the first one whose `min_score` the total meets wins.
4. Return:

```json
{
  "score": 87.5,
  "severity": "high",
  "alert_type": "within_1_hour",
  "factors": {
    "data_sensitivity": {"value": "pii", "score": 80},
    "policy_relevance": {"value": "direct_violation", "score": 100},
    "frequency": {"value": "first_occurrence", "score": 30},
    "user_role": {"value": "standard_user", "score": 20}
  }
}
```

## Pairs well with

- `analyze-risk` (upstream)
- `send-alert` (downstream — uses `alert_type` for routing)
