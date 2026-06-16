# trust-agent

Runtime AI usage monitoring for GRC engineering. Assesses AI prompts and outputs for data exposure, scores risk, maps violations to compliance frameworks, routes alerts, and generates audit-ready reports.

## What it does

Given a stream of AI usage events (prompt, output, user, timestamp, token count), trust-agent runs each event through a five-step pipeline:

1. **Analyze** the prompt and output for sensitive data (PII, credentials, proprietary, internal, public)
2. **Classify** risk using weighted factors (data sensitivity, policy relevance, frequency, user role)
3. **Check policy** with deterministic regex rules (SSN, credit cards, API keys, passwords, connection strings, off-hours usage, bulk data extraction)
4. **Map compliance** against GDPR, SOC2, ISO 27001, and NIST AI RMF
5. **Route alerts** by severity (immediate, within 1 hour, daily, weekly, monthly) and produce structured reports

## Why this exists

Most GRC engineering focuses on infrastructure controls: cloud posture, IAM, network, drift. AI usage is the emerging gap. Policies exist on paper, but there is no runtime observation of how people actually use LLMs and no feedback loop when they leak secrets, paste customer PII, or exfiltrate data through a chat UI.

trust-agent is the application-layer counterpart to the rest of this portfolio. It fills the gap between policy documents and enforcement.

## Architecture

### Tools (Python)

| File | Purpose |
|---|---|
| `tools/policy_engine.py` | Regex-based violation detection |
| `tools/risk_scorer.py` | Weighted severity scoring |
| `tools/compliance_mapper.py` | Framework enrichment (GDPR, SOC2, ISO 27001, NIST AI RMF) |
| `tools/report_builder.py` | Daily, weekly, and monthly JSON reports |

### Configuration (YAML)

| File | Purpose |
|---|---|
| `context/policies.yaml` | Policy definitions and business hours |
| `context/risk_thresholds.yaml` | Scoring weights and severity thresholds |
| `context/compliance_maps.yaml` | Framework reference tables |

### Companion skills

Eight Claude Code skills ship in `skills/` and mirror the tool pipeline. Each SKILL.md is self-contained (patterns, scoring weights, and framework mappings are inlined) so the skills can run independently of the Python tools and produce the same structured outputs:

`analyze-risk`, `classify-risk`, `check-policy`, `map-compliance`, `detect-patterns`, `send-alert`, `generate-report`, `monitor-loop`

To make them invokable from any Claude Code session, copy them into your user skills directory:

```bash
# macOS / Linux / Git Bash on Windows
cp -r skills/* ~/.claude/skills/
```

```powershell
# Windows PowerShell
Copy-Item -Recurse skills\* $HOME\.claude\skills\
```

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/tiffanymwr15/trust-agent.git
cd trust-agent
python -m pip install -r requirements.txt
```

Verify each tool runs standalone:

```bash
python tools/policy_engine.py      # prints sample violations
python tools/risk_scorer.py        # prints sample score + severity
python tools/compliance_mapper.py  # prints sample framework refs
python tools/report_builder.py     # prints sample JSON report
```

## Usage

### 1. Run the pipeline on the bundled sample

```bash
python run_batch.py sample_data/events.json
```

You will see a per-event breakdown followed by a summary report. The JSON report is saved under `reports/`.

### 2. Run it on your own events

Create a JSON file containing a list of events that match the schema below, then point `run_batch.py` at it:

```bash
python run_batch.py path/to/your_events.json --report-type weekly
```

`--report-type` accepts `daily`, `weekly`, or `monthly`. Defaults to `daily`.

### 3. Event schema

Each event is a JSON object. Fields marked required are needed for meaningful checks.

| Field | Type | Required | Description |
|---|---|---|---|
| `event_id` | string | yes | Unique ID for the event |
| `user` | string | yes | User identifier (email, username, UUID) |
| `user_role` | string | recommended | `admin`, `privileged`, `standard_user`, or `external` |
| `team` | string | recommended | Team name for grouping in reports |
| `timestamp` | string (ISO 8601) | recommended | Used for off-hours detection |
| `prompt` | string | yes | The text sent to the LLM |
| `output` | string | yes | The LLM's response |
| `token_count` | integer | recommended | Used for bulk-extraction detection |

Example:

```json
{
  "event_id": "evt-100",
  "user": "alice@example.com",
  "user_role": "standard_user",
  "team": "engineering",
  "timestamp": "2026-04-14T09:15:00Z",
  "prompt": "Please summarize this customer ticket...",
  "output": "Summary: the customer is requesting...",
  "token_count": 240
}
```

### 4. Understanding the output

Per-event console output shows every violation with its severity, the pattern that matched, and the compliance frameworks it maps to. Example:

```
[evt-005] eve@example.com (contractor)
  [CRITICAL] CREDENTIALS_IN_PROMPT (api_key)
    frameworks: gdpr, soc2, iso27001, nist_ai_rmf
  [LOW] OFF_HOURS_USAGE (Usage at hour 22:00 UTC)
    frameworks: soc2, iso27001, nist_ai_rmf
```

The saved JSON report (`reports/<type>_<timestamp>.json`) contains:

- `summary.total_events_analyzed`, `summary.total_violations`
- `summary.severity_breakdown` — count by severity level
- `summary.top_violations` — counts grouped by `policy_id`
- `summary.team_activity` — events grouped by team
- `critical_findings` and `high_findings` — full records for escalation
- `recommendations` — actionable guidance generated from the findings

### 5. Using the skills from Claude Code

Install the bundled skills into your user skills directory (see the **Companion skills** section under Architecture above), then in any Claude Code session invoke:

```
/monitor-loop path/to/your_events.json
```

`monitor-loop` orchestrates all seven other skills. You can also invoke any skill individually (`/analyze-risk`, `/check-policy`, `/generate-report`, etc.).

## Compliance framework coverage

Every mapped policy violation returns references across four frameworks:

| Framework | Coverage |
|---|---|
| GDPR | Art. 5, Art. 25, Art. 32 |
| SOC2 | CC6.1, CC6.3, CC6.7, CC7.2 |
| ISO 27001 | A.8.2.3, A.9.2.4, A.9.4.3, A.12.4.1, A.13.2.1 |
| NIST AI RMF | GOVERN-1.1, MAP-4.1, MANAGE-2.2, MANAGE-3.1, MEASURE-2.7 |

Extend by adding entries to `context/compliance_maps.yaml`. No code change required.

## How it fits with the rest of grc-portfolio

trust-agent is designed to feed the existing portfolio scripts, not replace them.

| Upstream output | Downstream portfolio tool |
|---|---|
| Per-event violations | `ai_risk_register.py` (convert manual entries to live) |
| Compliance-mapped findings | `evidence_logger.py` (audit trail) |
| Severity-routed alerts | `grc_alerter.py` (replace stub sink) |
| Batch reports | `grc_dashboard.py`, `compliance_report.py` |
| Framework references | `control_mapper.py` (eventual unification target) |

## Where AI governance fits more broadly

trust-agent is one layer in a three-part AI governance stack:

1. **AI GRC Policy Generator** (separate project) writes the policies that reference ISO 42001, NIST AI RMF, and the EU AI Act
2. **trust-agent** (this project) enforces those policies at runtime against real AI usage events
3. **AI Agents Lab** (course work) builds the AI systems being governed

Together this is the full loop: author policy, deploy controls, observe and alert, generate evidence.

## Recommended deployment: Tailnet + Aperture

trust-agent runs standalone on any JSON event stream, but it is **best paired with an
[Aperture](https://github.com/) AI gateway fronted by a Tailscale tailnet**. That upstream gives
trust-agent the clean, identity-attributed event feed it is designed for:

- **Aperture** sits between users and LLM providers and emits a per-session audit trail —
  who, which model, tokens, cost, timestamp — in the exact shape `run_batch.py` consumes.
  No manual log wrangling; point the pipeline at Aperture's session export (or poll its API).
- **Tailnet (Tailscale)** supplies the identity layer. Every request is attributed to a real
  tailnet member with no API keys in repos, so the `user` / `user_role` fields are trustworthy
  and the compliance mappings (access control, accountability) actually hold up in an audit.

Without this pairing you must supply your own event source and identity attribution, and PII/
identity fields may be unreliable. With it, the loop is fully automated and audit-ready.

> **Note:** When ingesting directly from Aperture, the gateway wraps session identity into the
> `prompt` field (`"Session for user <email>: N request(s), models: ..."`). `tools/policy_engine.py`
> strips this metadata before PII scanning so the wrapper email does not false-positive every
> session. See `skills/check-policy/SKILL.md` for details.

## Requirements

- Python 3.10+
- PyYAML 6.0+

Runs on any system with Python. No cloud dependencies, no external services, no Monday.com integration. The tools use relative paths so the project is portable.

**Recommended (not required):** A Tailscale tailnet + Aperture AI gateway upstream — this is the deployment the skills work best with, supplying an identity-attributed, audit-ready event feed automatically. See **Recommended deployment: Tailnet + Aperture** above.

## Extending

- **New violation types**: add a regex to `PII_PATTERNS` or `CREDENTIAL_PATTERNS` in `tools/policy_engine.py`, then add a matching entry in `context/compliance_maps.yaml`
- **New frameworks**: add a `frameworks` entry in `context/compliance_maps.yaml` with your mappings
- **New severity bands**: edit `context/risk_thresholds.yaml`
- **New reports**: extend `generate_report` in `tools/report_builder.py`

## Status

v1.0. Smoke-tested against a five-event sample batch covering credentials in prompts, PII in prompts, off-hours usage, bulk data extraction, and an external contractor exposure case. All four frameworks mapped. All conditional recommendations fire correctly.

## License

MIT License. See [LICENSE](LICENSE).
