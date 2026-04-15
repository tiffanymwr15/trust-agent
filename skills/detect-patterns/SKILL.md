---
name: detect-patterns
description: Analyze historical event and violation data to identify systemic risks, recurring issues, and anomalies. Compares current findings against historical baselines to flag escalating trends. Use periodically after processing batches of events or when asked to find trends.
user-invocable: true
---

# Detect Patterns

Find systemic risks across many events, not just single-event violations.

## When to use

- After processing a batch of events through `analyze-risk` / `check-policy`
- On a schedule (end of day, end of week)
- When a stakeholder asks "are we seeing any trends?"

## Input

A historical record of events and violations (from memory, a log file, or a provided dataset). Each record should carry enough metadata to group by: `user`, `team`, `policy_id`, `timestamp`, `severity`.

## Patterns to look for

1. **Repeat offenders** — same `user` triggering ≥3 violations in the period
2. **Hot teams** — same `team` accounting for a disproportionate share of violations
3. **Escalating frequency** — violation count for a given `policy_id` rising week-over-week
4. **Novel violation types** — `policy_id` values appearing for the first time
5. **Time-based clusters** — violations concentrated in specific hours or days
6. **Severity drift** — average severity trending upward

## Instructions

1. Group the input by user, team, `policy_id`, and time bucket.
2. For each pattern above, compute the metric and compare to a baseline (prior period, or the first half of the window vs the second half).
3. Flag anything meeting a threshold:
   - Repeat offender: ≥3 violations from same user
   - Hot team: >40% of period's violations from one team
   - Escalating: >50% week-over-week increase
   - Novel: first appearance in the last 30 days
   - Time cluster: >3× expected rate for an hour/day
4. Return a structured findings list:

```json
{
  "patterns": [
    {
      "type": "repeat_offender",
      "subject": "user:alice@example.com",
      "count": 5,
      "severity_mix": {"critical": 1, "high": 2, "medium": 2},
      "evidence": ["event_id_1", "event_id_2", "..."]
    }
  ],
  "period": "2026-04-07 to 2026-04-14",
  "events_analyzed": 1240
}
```

5. Store your findings so the next run can compare against this baseline.

## Improvement over time

This skill gets sharper as it accumulates history. Preserve prior pattern findings — next run, note whether flagged patterns persisted, resolved, or escalated.
