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

## Aggregating across many events (avoid low-severity saturation)

The scoring above is **per-event**. When rolling many events into a single overall
score, do **not** simply sum severity weights and clamp to 100 — a high *volume* of
low-severity findings (e.g. 50 `OFF_HOURS_USAGE` flags) will saturate the total and
falsely read "critical".

The repo's batch flow sidesteps this by reporting a `severity_breakdown` (counts per
level) rather than one rolled-up number — counts can't saturate. If you do need a single
aggregate score, bound it by the **highest severity actually present**:

- **Floor** = bottom of that severity's band, so a single real `critical` finding always
  reads critical even though its additive weight alone is small.
- **Cap** = top of that severity's band, so volume of lower-severity findings can elevate
  the score *within* the band but never cross into a higher one.

```python
# highest = most severe level present among the violations
floor = risk_levels[highest]['min_score']          # e.g. critical -> 90
cap   = {'critical':100,'high':89,'medium':69,'low':39,'info':19}[highest]
score = max(min(additive_total, cap, 100), floor)
```

Result: 50 low-only findings → low band (never critical); 1 credential leak → critical
regardless of how few findings there are.

## Pairs well with

- `analyze-risk` (upstream)
- `send-alert` (downstream — uses `alert_type` for routing)
