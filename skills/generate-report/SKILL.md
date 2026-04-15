---
name: generate-report
description: Create structured compliance and risk reports (daily, weekly, or monthly) from analyzed events and violations. Includes summary stats, severity breakdowns, top violations, critical findings, and recommendations. Use on schedule or when requested.
user-invocable: true
argument-hint: "[daily|weekly|monthly]"
---

# Generate Report

Produce a structured compliance/risk report from a set of events and violations.

## When to use

- On schedule: end of day (daily), end of week (weekly), end of month (monthly)
- On request: "give me this week's compliance posture", "what did we find this month?"

## Input

- `events` — list of processed AI usage events
- `violations` — list of policy violations (ideally already enriched by `map-compliance`)
- `report_type` — `daily` | `weekly` | `monthly` (default `daily`)

## Report structure

```json
{
  "report_type": "weekly",
  "generated_at": "2026-04-14T12:00:00Z",
  "period": "weekly",
  "summary": {
    "total_events_analyzed": 1240,
    "total_violations": 37,
    "severity_breakdown": {"critical": 2, "high": 8, "medium": 15, "low": 10, "info": 2},
    "top_violations": {"PII_IN_PROMPT": 18, "CREDENTIALS_IN_PROMPT": 4},
    "team_activity": {"engineering": 612, "hr": 204}
  },
  "critical_findings": [],
  "high_findings": [],
  "recommendations": []
}
```

## Report content by type

- **Daily** — key metrics, new violations, trend indicators vs previous day
- **Weekly** — pattern analysis (pair with `detect-patterns`), compliance posture, week-over-week deltas, recommendations
- **Monthly** — risk score trends, compliance status by framework, team comparisons, quarter-to-date rollup

## Instructions

1. Count events and violations; compute severity and policy breakdowns.
2. Extract `critical_findings` and `high_findings` as full violation records (not just counts).
3. Generate `recommendations` based on what the data shows:
   - Any critical: "IMMEDIATE: Review and rotate all exposed credentials"
   - Any high PII: "HIGH PRIORITY: Implement data masking for AI prompts containing PII"
   - Any BULK_DATA_EXTRACTION: "Review data extraction patterns and enforce DLP controls"
   - Any OFF_HOURS_USAGE: "Audit off-hours AI usage for unauthorized access"
4. Save the report as JSON to a `reports/` directory with filename `{report_type}_{YYYYMMDD_HHMMSS}.json`.
5. Return the report object and the saved path.

## Delivery

Pair with `send-alert` or a messaging gateway to deliver the report summary to stakeholders. The saved JSON is the system of record; the message is the human-readable summary.
