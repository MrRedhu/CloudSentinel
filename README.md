# CloudSentinel

**AI-powered AWS security triage.** CloudSentinel turns a raw Amazon GuardDuty
finding into a validated, grounded incident brief and delivers it to Slack —
automatically, with no human in the loop.

```
GuardDuty finding → EventBridge → Lambda
    → enrich (CloudTrail + IAM blast radius + related findings)
    → sanitize (prompt-injection containment)
    → Claude Opus 4.8 (structured output)
    → validate + ground (ATT&CK allowlist, drop hallucinated resources)
    → re-score severity
    → Slack + S3 (full report) + DynamoDB (audit)
```

If Claude is unavailable, a **degraded path** still delivers the raw enriched
context to Slack, so an analyst is never left blind.

## Why it's defensible (design highlights)

- **Least privilege, no remediation.** The Lambda role can *read* telemetry and
  *notify* humans — nothing else. No `iam:*` writes, no compute mutation, no
  deletes. A compromised analyzer can post a Slack message; it cannot touch
  infrastructure. (See `terraform/iam.tf`.)
- **Prompt-injection defense.** All untrusted telemetry is structurally contained
  before it reaches the model — JSON-encoded, control-characters stripped, wrapped
  in delimiters it cannot escape. An attacker who names a bucket
  "ignore previous instructions" gets analyzed, not obeyed. (See
  `src/security/sanitizer.py`.)
- **Grounded output.** Structured outputs guarantee the JSON shape; a validator
  then rejects invented MITRE ATT&CK technique IDs and drops any resource that
  doesn't appear in the evidence. (See `src/analysis/validator.py`.)
- **Secrets only in Secrets Manager** — never in code, env files, or Terraform
  state.

## Status

Active build. **Stage A (local foundation) is complete:** the Python analysis
core, prompt-injection sanitizer, dedup gate, deterministic severity re-scorer,
and the full Terraform are written and tested. **Stage B** (deploy to AWS,
generate real attack telemetry with Stratus Red Team, wire enrichment + delivery)
and **Stage C** (CLI, observability, evaluation harness, docs) follow.

## Tech

Python 3.12 (AWS Lambda) · Anthropic Claude Opus 4.8 (structured outputs,
adaptive thinking, prompt caching) · Terraform · GuardDuty / EventBridge /
CloudTrail / DynamoDB / S3 / SNS / Secrets Manager · Stratus Red Team.

## Local development

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows;  source .venv/bin/activate on *nix
pip install -r requirements-dev.txt
pytest                        # unit + golden tests (no AWS, no API key)
ruff check .
pre-commit install            # gitleaks blocks secrets before they're committed
```

Terraform is validated but not yet applied (Stage B):

```bash
cd terraform && terraform init -backend=false && terraform validate
```

## Repository layout

```
src/security/      prompt-injection sanitizer, dedup gate
src/analysis/      schema, system prompt, Claude client, validator, severity scorer
src/enrichment/    CloudTrail / IAM / related-findings enrichment (Stage B)
src/output/        Slack / S3 / DynamoDB delivery + degraded path (Stage B)
terraform/         least-privilege infrastructure as code
tests/             unit + golden tests
```
