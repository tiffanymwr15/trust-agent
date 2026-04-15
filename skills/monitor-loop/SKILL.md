---
name: monitor-loop
description: Main orchestration loop that ties all trust/governance skills together. Runs analyze-risk, classify-risk, check-policy, map-compliance, send-alert, detect-patterns, and generate-report in sequence for a batch of AI usage events. Use as the primary entry point for continuous AI usage monitoring.
user-invocable: true
argument-hint: "[path to events file or directory]"
---

# Monitor Loop

Orchestrates all other trust/governance skills. This is the primary entry point.

## When to use

When the user wants to process a batch (or stream) of AI usage events end-to-end: assess, score, check, enrich, alert, and report.

## Input

- An events source: a JSON/JSONL file, a directory of event files, or an inline list

## Instructions

1. **Load events** from the provided source.
2. **Per event**, run in sequence:
   - `analyze-risk` → get `data_sensitivity` + `policy_relevance` + findings
   - `classify-risk` → get `score`, `severity`, `alert_type`
   - `check-policy` → get regex-based violations
   - If violations exist: `map-compliance` → enrich with framework references
   - If `severity` ∈ {critical, high}: `send-alert` immediately
3. **Store** every event + analysis + violations tuple in memory/log for later pattern detection and reporting.
4. **After the batch**, run `detect-patterns` across the accumulated history.
5. **On schedule** (caller-provided), run `generate-report`.
6. **Audit trail** — log every skill invocation with timestamp, event ID, and outcome.

## Self-improvement

- Refine prompts used by `analyze-risk` as you learn what the team's actual data looks like.
- When a novel violation type surfaces that doesn't fit `check-policy`'s rules, propose a new pattern to add.
- When a pattern from `detect-patterns` repeats across batches, escalate it for policy review.

## Example flow

```
Load 50 events from sample_data/events.jsonl
  → event 1: analyze-risk → classify-risk (medium) → check-policy (1 violation)
              → map-compliance → [batched for daily_summary]
  → event 2: analyze-risk → classify-risk (critical) → check-policy (2 violations)
              → map-compliance → send-alert (immediate)
  ...
Batch complete
  → detect-patterns across all 50 + prior history
  → generate-report (daily) → delivered via gateway
```

## Pairs well with

All other trust/governance skills (`analyze-risk`, `classify-risk`, `check-policy`, `map-compliance`, `detect-patterns`, `send-alert`, `generate-report`).
