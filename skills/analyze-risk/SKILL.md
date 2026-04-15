---
name: analyze-risk
description: Analyze an AI usage event for potential data risks using NLP. Inspects prompt and output fields for PII, credentials, and proprietary data, then classifies sensitivity and policy relevance. Use when a new AI usage event needs to be evaluated for sensitive data exposure.
user-invocable: true
---

# Analyze Risk

Assess a single AI usage event (prompt + output + metadata) for data exposure risks.

## When to use

When the user provides an AI usage event (a prompt sent to an LLM, plus its output and metadata) and wants to know whether sensitive data was exposed and how relevant it is to policy.

## Input

An event object (JSON or equivalent) containing at minimum:
- `prompt` — the text sent to the model
- `output` — the model's response
- Optional: `user_role`, `team`, `timestamp`, `token_count`

## Instructions

1. Read the `prompt` and `output` fields carefully.
2. Scan for each data category:
   - **PII** — SSNs, credit card numbers, email addresses, phone numbers, street addresses, DOB, government IDs
   - **Credentials** — API keys, passwords, connection strings, bearer tokens, private keys, OAuth secrets
   - **Proprietary** — internal financial records, customer lists, strategy documents, unreleased product details, source code with business logic
   - **Internal** — non-public employee info, org charts, internal memos
   - **Public** — press releases, published docs, public marketing copy
3. Classify `data_sensitivity` as the highest category present: `credentials` > `pii` > `proprietary` > `internal` > `public`.
4. Determine `policy_relevance`:
   - `direct_violation` — explicit policy breach (e.g., credentials pasted into a third-party LLM)
   - `potential_violation` — ambiguous case that likely violates policy
   - `best_practice` — not a violation but a pattern worth coaching on
   - `informational` — benign use
5. Return a structured analysis:

```json
{
  "data_sensitivity": "credentials|pii|proprietary|internal|public",
  "policy_relevance": "direct_violation|potential_violation|best_practice|informational",
  "findings": ["short description of each concrete finding"],
  "reasoning": "why you reached this classification"
}
```

## Pairs well with

- `classify-risk` — takes this analysis and produces a severity score
- `check-policy` — regex-based complement that catches patterns NLP might miss
