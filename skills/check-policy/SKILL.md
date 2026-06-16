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
4. **OFF_HOURS_USAGE** (low) — the event's `timestamp` (assumed UTC) falls outside business hours after conversion to the configured timezone. The window is read from `context/policies.yaml` → `business_hours` (`start`, `end`, `timezone`). The `timezone` is an IANA name (e.g. `UTC`, `America/New_York`), so DST (EST↔EDT) is handled automatically; set it to your operating zone. Defaults to 08:00–18:00 UTC if unset.
5. **BULK_DATA_EXTRACTION** (high) — `token_count` > 1000.

## Instructions

1. **Strip gateway session metadata from `prompt` before PII scanning** (see pitfall below).
2. Run each pattern against the relevant field (case-insensitive).
3. Record every match as a violation with `policy_id`, `severity`, `pattern_matched` (or `detail`), and `location`.
4. Parse the hour from `timestamp[11:13]` and apply the business-hours check.
5. Check the token count.
6. Return the full list of violations (may be empty).

## Pitfall: gateway metadata causes false-positive PII

Aperture (and similar gateways) embed session identity into the `prompt` field as metadata, e.g.:

```
Session for user user@example.com: 4 request(s), models: minimax/minimax-m2.5
```

The `email_address` PII pattern matches the user's address in this gateway-generated
context — NOT user-authored input — flagging **every** session with `PII_IN_PROMPT` and
saturating the risk score. A lookbehind on the email regex does **not** fix this (the email
is followed by `:`, not preceded by one).

**Fix:** strip the metadata line before scanning. `tools/policy_engine.py` implements:

```python
APERTURE_META_PREFIX = re.compile(
    r'^Session for user\s+\S+:\s*\d+\s+request\(s\),\s*models:.*$',
    re.IGNORECASE | re.MULTILINE,
)

def strip_session_metadata(prompt: str) -> str:
    return APERTURE_META_PREFIX.sub('', prompt).strip()

# in check_event():
prompt = strip_session_metadata(event.get('prompt', ''))
```

Only the metadata line is removed — real PII/credentials in genuine prompt content
(anything after the metadata line) are still detected. Re-verify the regex against a fresh
sample whenever the gateway changes its session-metadata wording.

## Pitfall: `null` numeric fields when ingesting live gateway sessions

When pulling sessions directly from a gateway API (rather than `sample_data/events.json`),
fields like `total_estimated_cost_dollars` or `total_output_tokens` can be present but
`null`. `dict.get(key, 0)` returns the default **only when the key is missing** — an explicit
`null` returns `None`, which crashes on `f"{...:.6f}"` formatting or on `int + None` arithmetic
(`TypeError: unsupported format string passed to NoneType.__format__`).

**Fix:** coerce with `or` instead of relying on the `.get()` default:

```python
session.get('total_estimated_cost_dollars') or 0          # not .get(key, 0)
(session.get('total_input_tokens') or 0) + (session.get('total_output_tokens') or 0)
session.get('models') or []
```

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
