---
name: map-compliance
description: Map policy violations to regulatory compliance frameworks (GDPR, SOC2, ISO 27001, NIST AI RMF). Enriches each violation with framework references and descriptions. Use after check-policy has identified violations that need compliance context.
user-invocable: true
---

# Map Compliance

Enrich policy violations with regulatory framework references.

## When to use

After `check-policy` (or any source) has produced a list of violations with `policy_id` fields, and Trust / Legal / Security stakeholders need to understand regulatory impact.

## Input

A list of violations, each with at least a `policy_id`.

## Framework mappings

### PII_IN_PROMPT

| Framework      | References                         | Description                                               |
|----------------|-------------------------------------|-----------------------------------------------------------|
| GDPR           | Art. 5 (data minimisation), Art. 32 | Personal data must be minimized and protected             |
| SOC2           | CC6.1, CC6.7                        | Logical access and data transmission controls             |
| ISO 27001      | A.8.2.3, A.13.2.1                   | Information handling and transfer                          |
| NIST AI RMF    | GOVERN-1.1, MAP-4.1                 | Accountability and risk identification                    |

### CREDENTIALS_IN_PROMPT / CREDENTIALS_IN_OUTPUT

| Framework      | References            | Description                                      |
|----------------|-----------------------|--------------------------------------------------|
| GDPR           | Art. 32               | Security of processing                           |
| SOC2           | CC6.1, CC6.3          | Access controls and credential management       |
| ISO 27001      | A.9.2.4, A.9.4.3      | Secret authentication information management    |
| NIST AI RMF    | MANAGE-2.2            | Risk response to identified threats             |

### OFF_HOURS_USAGE

| Framework      | References    | Description                              |
|----------------|---------------|------------------------------------------|
| SOC2           | CC7.2         | Anomalous activity monitoring            |
| ISO 27001      | A.12.4.1      | Event logging                            |
| NIST AI RMF    | MEASURE-2.7   | Monitoring AI system performance         |

### BULK_DATA_EXTRACTION

| Framework      | References         | Description                              |
|----------------|--------------------|------------------------------------------|
| GDPR           | Art. 5, Art. 25    | Data minimisation and privacy by design  |
| SOC2           | CC6.7              | Data transmission restrictions           |
| ISO 27001      | A.13.2.1           | Transfer of information                  |
| NIST AI RMF    | MANAGE-3.1         | AI system risk management                |

## Instructions

1. For each violation in the input list, look up its `policy_id` in the mappings above.
2. Build a `compliance` object keyed by framework, each containing `framework_name`, `references`, `description`.
3. If a violation has no mapping, return an empty `compliance` object (do not drop the violation).
4. Return the original violation list with `compliance` added to each item.

```json
{
  "policy_id": "CREDENTIALS_IN_PROMPT",
  "severity": "critical",
  "compliance": {
    "gdpr": {
      "framework_name": "GDPR",
      "references": ["Art. 32"],
      "description": "Security of processing"
    }
  }
}
```

## Extending

When new `policy_id` values appear, add a row to the mappings above rather than hardcoding logic in a caller.
