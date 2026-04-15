---
name: send-alert
description: Route alerts based on severity using a messaging gateway. Handles immediate, hourly, daily, weekly, and monthly alert types with deduplication. Use when a violation requires notification based on its severity level.
user-invocable: true
---

# Send Alert

Route a classified violation to the right destination at the right time.

## When to use

After `classify-risk` has produced a severity + `alert_type` for a violation and the user wants it delivered to stakeholders.

## Input

- A violation (with `policy_id`, `severity`, `compliance` context, affected `user`/`team`)
- An `alert_type` from `classify-risk`: `immediate`, `within_1_hour`, `daily_summary`, `weekly_report`, `monthly_report`
- A messaging gateway reference (Slack webhook, email, PagerDuty, etc. — whatever the caller provides)

## Routing rules

| alert_type      | Action                                          |
|-----------------|--------------------------------------------------|
| immediate       | Send now. Do not batch.                          |
| within_1_hour   | Send promptly, may coalesce with peers.          |
| daily_summary   | Buffer for the next daily digest.                |
| weekly_report   | Buffer for the weekly report.                    |
| monthly_report  | Buffer for the monthly report.                   |

## Alert payload

Every alert (immediate or batched) should include:

- Severity label
- Policy that was violated
- Compliance impact (framework references from `map-compliance`)
- Affected user and team
- Concrete remediation steps
- Link/ID to the underlying event

## Instructions

1. Check the `alert_type`.
2. Before sending an `immediate` or `within_1_hour` alert, check memory for a recent alert covering the same `policy_id` + same user within the last hour. If found, suppress (deduplicate) and just increment the count on the existing alert record.
3. Format the payload with the fields above.
4. For immediate / hourly: dispatch via the messaging gateway now.
5. For daily / weekly / monthly: append to the appropriate batch buffer.
6. Record the alert in memory with timestamp, policy_id, user, and delivery status — for deduplication, escalation tracking, and audit.

## Escalation

If a `daily_summary`-level alert repeats 3+ times in one day from the same user, escalate to `within_1_hour` for the next occurrence.
