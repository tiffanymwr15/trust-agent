---
name: check-policy
description: Evaluate an AI usage event against policy rules using regex pattern matching. Detects PII, credentials, off-hours usage, and bulk data extraction. Use for every AI usage event that needs policy compliance checking.
user-invocable: true
---

# Check Policy

Regex-based policy rule engine. Complements the NLP-based `analyze-risk` skill.

## When to use

For every AI usage event that needs deterministic policy checking. Run alongside `analyze-risk` — regex catches patterns NLP can miss, NLP catches intent regex can miss.

## Input

An event with:
- `prompt` (string)
- `output` (string)
- `timestamp` (ISO 8601 string, optional)
- `token_count` (int, optional)

## Pattern library

### PII patterns

| Name                    | Regex                                                          |
|-------------------------|----------------------------------------------------------------|
| social_security_number  | `\b\d{3}-\d{2}-\d{4}\b`                                        |
| credit_card_number      | `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`                   |
| email_address           | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`           |
| phone_number            | `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`                                |

### Credential patterns

| Name              | Regex                                                      |
|-------------------|------------------------------------------------------------|
| api_key           | `(sk-[a-zA-Z0-9]{20,}\|key-[a-zA-Z0-9]{20,}\|AKIA[0-9A-Z]{16})` |
| password          | `(password\|passwd\|pwd)\s*[:=]\s*\S+`                     |
| connection_string | `(postgresql\|mysql\|mongodb\|redis):\/\/[^\s]+`           |
| secret_key        | `(secret\|token\|bearer)\s*[:=]\s*\S+`                     |
| private_key       | `-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`                 |

## Rules

1. **PII_IN_PROMPT** (high) — any PII pattern matches `prompt`.
2. **CREDENTIALS_IN_PROMPT** (critical) — any credential pattern matches `prompt`.
3. **CREDENTIALS_IN_OUTPUT** (critical) — any credential pattern matches `output`.
4. **OFF_HOURS_USAGE** (low) — `timestamp` hour is outside 08:00–18:00 UTC.
5. **BULK_DATA_EXTRACTION** (high) — `token_count` > 1000.

## Instructions

1. Run each pattern against the relevant field (case-insensitive).
2. Record every match as a violation with `policy_id`, `severity`, `pattern_matched` (or `detail`), and `location`.
3. Parse the hour from `timestamp[11:13]` and apply the business-hours check.
4. Check the token count.
5. Return the full list of violations (may be empty).

```json
[
  {
    "policy_id": "CREDENTIALS_IN_PROMPT",
    "pattern_matched": "connection_string",
    "location": "prompt",
    "severity": "critical"
  }
]
```

## Pairs well with

- `analyze-risk` (complementary NLP check)
- `map-compliance` (enriches these violations with framework references)
