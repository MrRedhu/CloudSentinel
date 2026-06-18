# CloudSentinel

**AI-powered AWS security triage.** CloudSentinel turns a raw Amazon GuardDuty
finding into a validated, grounded incident brief and delivers it to Slack —
automatically, with no human in the loop.

```
GuardDuty finding → EventBridge → Lambda
    → dedup gate (idempotent)
    → enrich (CloudTrail timeline + IAM blast radius + related findings)
    → sanitize (prompt-injection containment)
    → Claude Opus 4.8 (structured output, adaptive thinking)
    → validate + ground (ATT&CK allowlist, drop hallucinated resources)
    → re-score severity (deterministic)
    → Slack + S3 (full report) + DynamoDB (audit) + CloudWatch metrics
```

If Claude is unavailable, a **degraded path** still delivers the raw enriched
context to Slack, so an analyst is never left blind.

## Status — deployed and validated end-to-end

Running live in an AWS sandbox. A real GuardDuty finding flows through EventBridge
to the Lambda and produces a Slack brief automatically, no human touch. Measured
against the deployed system:

| Metric | Result |
|---|---|
| Severity-match accuracy | **88%** (7/8 labeled findings) |
| Mean time-to-triage | **~12.7 s** |
| Prompt-cache reads (back-to-back) | 7,460 tokens at ~0.1× cost |
| Tests | **64 passing** (unit + golden + moto integration) |

## Why it's defensible (design highlights)

- **Least privilege, no remediation.** The Lambda role can *read* telemetry and
  *notify* humans — nothing else. No `iam:*` writes, no compute mutation, no
  deletes. A compromised analyzer can post a Slack message; it cannot touch
  infrastructure. (`terraform/iam.tf`)
- **Prompt-injection defense.** All untrusted telemetry is structurally contained
  before it reaches the model — JSON-encoded, control/format characters stripped,
  wrapped in delimiters it cannot escape. An attacker who names a bucket
  "ignore previous instructions" gets analyzed, not obeyed. (`src/security/sanitizer.py`)
- **Grounded output.** Structured outputs guarantee the JSON shape; a validator
  then rejects invented MITRE ATT&CK technique IDs and drops any resource that
  doesn't appear in the evidence. (`src/analysis/validator.py`)
- **Secrets only in Secrets Manager** — never in code, env files, or Terraform state.
- **Never goes dark.** Refusal, API error, or model output that ignores the
  constraints all fall through to a degraded Slack message with the raw context.

See [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) for the full rationale
(including why Opus 4.8 over Fable 5, and where prompt caching actually helps),
and [`docs/sample_output.md`](docs/sample_output.md) for real briefs.

## Before / after

**Before** — a raw GuardDuty finding: a type string, a severity number, an access
key id, a principal. No context, no recommended actions, no MITRE mapping.

**After** — a grounded brief (real Opus 4.8 output):

> **HIGH** · confidence `medium` · `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
>
> Temporary credentials for the EC2 instance role `app-server-role` were used from
> an IP outside AWS — the classic signature of stolen instance-role credentials
> being exploited off the instance… No CloudTrail activity was provided and the IAM
> blast radius is UNKNOWN, so follow-on actions cannot be confirmed — confidence is
> reduced accordingly.
>
> **MITRE ATT&CK:** `T1552.005` Cloud Instance Metadata API · `T1078.004` Valid Cloud Accounts
> **Actions:** 1) Revoke the role's active sessions… 2) Pull CloudTrail for the access key… 3) …

## Tech

Python 3.12 (AWS Lambda) · Anthropic Claude Opus 4.8 (structured outputs via
`messages.parse`, adaptive thinking, prompt caching) · Terraform · GuardDuty /
EventBridge / CloudTrail / DynamoDB / S3 / SNS / Secrets Manager / CloudWatch ·
Stratus Red Team.

## Usage

**CLI** (runs the same pipeline on demand and prints the brief):

```bash
python cli/cloudsentinel.py analyze --finding-id <id> --detector-id <detector>
python cli/cloudsentinel.py analyze --file tests/sample_findings/x.json
python cli/cloudsentinel.py analyze --finding-id <id> --deliver   # via deployed Lambda
```

**Evaluation harness** (accuracy + mean-time over labeled findings):

```bash
python eval/harness.py --detector-id <detector>
```

## Local development

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows;  source .venv/bin/activate on *nix
pip install -r requirements-dev.txt
pytest                        # 64 tests, no AWS / no API key
ruff check .
pre-commit install            # gitleaks blocks secrets before they're committed
```

## Deploy

```bash
cd terraform && terraform init && terraform apply
# then inject secrets out-of-band (never in Terraform state):
aws secretsmanager put-secret-value --secret-id cloudsentinel/anthropic-api-key --secret-string 'sk-ant-...'
aws secretsmanager put-secret-value --secret-id cloudsentinel/slack-webhook    --secret-string 'https://hooks.slack.com/...'
```

The Lambda dependency layer (anthropic + pydantic) is built for the Lambda runtime
before apply:

```bash
pip install --platform manylinux2014_x86_64 --implementation cp --python-version 3.12 \
  --only-binary=:all: --target build/layer/python anthropic pydantic
# zip build/layer -> build/layer.zip   (terraform/layer.tf references it)
```

## Generating real attack telemetry (optional)

[Stratus Red Team](https://github.com/DataDog/stratus-red-team) detonates real,
benign attack techniques that produce genuine GuardDuty findings with real
CloudTrail trails:

```bash
stratus detonate aws.credential-access.ec2-steal-instance-credentials
# ... capture the GuardDuty finding, then:
stratus cleanup  aws.credential-access.ec2-steal-instance-credentials
```

## Repository layout

```
src/security/      prompt-injection sanitizer, dedup gate
src/analysis/      schema, system prompt, Claude client, validator, severity scorer
src/enrichment/    CloudTrail / IAM blast-radius / related-findings + enrich()
src/output/        Slack / S3 / DynamoDB delivery + degraded path
src/handler.py     Lambda orchestration
cli/               on-demand triage CLI
eval/              evaluation harness + labeled findings
terraform/         least-privilege infrastructure as code
tests/             64 unit + golden + moto integration tests
docs/              design decisions, sample output
```
