"""Lambda entrypoint: GuardDuty finding -> validated brief -> Slack/S3/DDB.

Orchestration only — every step lives in its own module. Flow:

    dedup gate -> enrich -> analyze (Claude) -> validate/ground (+1 retry)
    -> re-score severity -> persist (S3 + audit) -> Slack -> metrics

If analysis is unavailable or the model ignores the constraints, we fall through
to the degraded path: the raw enriched context still reaches Slack and the audit
table, flagged as un-analyzed. The triage is never dropped silently.
"""

from __future__ import annotations

import logging
import os
import time
from functools import lru_cache

import boto3

import metrics
from analysis import claude_client, severity_scorer, validator
from enrichment import enrich
from output import degraded, report, slack_formatter
from security.dedup import DedupStore

logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger("cloudsentinel.handler")

INPUT_PRICE_PER_TOKEN = 5.0 / 1_000_000
OUTPUT_PRICE_PER_TOKEN = 25.0 / 1_000_000


def _config() -> dict:
    return {
        "dedup_table": os.environ["DEDUP_TABLE"],
        "audit_table": os.environ["AUDIT_TABLE"],
        "reports_bucket": os.environ["REPORTS_BUCKET"],
        "detector_id": os.environ.get("GUARDDUTY_DETECTOR_ID"),
        "slack_secret_id": os.environ.get("SLACK_SECRET_ID", "cloudsentinel/slack-webhook"),
        "metrics_namespace": os.environ.get("METRICS_NAMESPACE", "CloudSentinel"),
        "region": os.environ.get("AWS_REGION", "us-east-1"),
    }


@lru_cache(maxsize=1)
def get_slack_webhook(secret_id: str) -> str | None:
    try:
        client = boto3.client("secretsmanager")
        return client.get_secret_value(SecretId=secret_id)["SecretString"]
    except Exception as exc:  # noqa: BLE001 - missing webhook -> skip posting, don't crash
        logger.warning("Could not read Slack webhook secret %s: %s", secret_id, exc)
        return None


def _console_url(region: str, bucket: str, key: str) -> str:
    return f"https://{region}.console.aws.amazon.com/s3/object/{bucket}?region={region}&prefix={key}"


def _analyze_with_retry(bundle: dict):
    """Analyze, validating the output; retry once if the model ignored constraints."""
    result = claude_client.analyze(bundle)
    if result.degraded:
        return result, None, result.reason

    validation = validator.validate_and_ground(result.brief, bundle)
    if validation.ok:
        return result, validation.brief, None

    # Model returned only invalid techniques -> one retry, then degrade.
    result = claude_client.analyze(bundle)
    if result.degraded:
        return result, None, result.reason
    validation = validator.validate_and_ground(result.brief, bundle)
    if validation.ok:
        return result, validation.brief, None
    return result, None, "validation_failed"


def _emit_metrics(config: dict, processing_ms: int, usage: dict | None, failed: bool):
    usage = usage or {}
    in_tok = usage.get("input_tokens") or 0
    out_tok = usage.get("output_tokens") or 0
    est_cost = in_tok * INPUT_PRICE_PER_TOKEN + out_tok * OUTPUT_PRICE_PER_TOKEN
    metrics.emit(
        config["metrics_namespace"],
        {
            "ProcessingTimeMs": processing_ms,
            "InputTokens": in_tok,
            "OutputTokens": out_tok,
            "EstCostUSD": est_cost,
            "Failures": 1 if failed else 0,
        },
    )


def process(finding: dict, *, config: dict | None = None) -> dict:
    """Triage one GuardDuty finding end-to-end."""
    config = config or _config()
    start = time.monotonic()

    # GuardDuty uses "Id" (GetFindings API) or "id" (EventBridge) — accept both.
    finding_id = finding.get("Id") or finding.get("id")
    if not finding_id:
        return {"status": "skipped", "reason": "no_finding_id"}

    dedup = DedupStore(config["dedup_table"])
    if not dedup.claim(finding_id):
        logger.info("Finding %s already triaged, skipping", finding_id)
        return {"status": "skipped", "reason": "already_triaged", "finding_id": finding_id}

    bundle = enrich(finding, detector_id=config["detector_id"])
    blast = bundle["iam_context"].get("blast_radius", "UNKNOWN")
    related_count = bundle["related_findings"].get("count", 0)
    gd_sev = bundle["finding"].get("severity") or 0

    result, brief, degraded_reason = _analyze_with_retry(bundle)
    processing_ms = int((time.monotonic() - start) * 1000)
    webhook = get_slack_webhook(config["slack_secret_id"])

    if brief is not None:
        final_sev = severity_scorer.rescore(gd_sev, blast, related_count, brief.severity)
        report_obj = {
            "finding": bundle["finding"],
            "enrichment": bundle,
            "brief": brief.model_dump(),
            "final_severity": final_sev,
            "usage": result.usage,
            "request_id": result.request_id,
        }
        key = report.persist_report(
            config["reports_bucket"], finding_id, report_obj, s3_client=boto3.client("s3")
        )
        report.write_audit(
            config["audit_table"],
            finding_id,
            ddb_resource=boto3.resource("dynamodb"),
            final_severity=final_sev,
            blast_radius=blast,
            action_count=len(brief.recommended_actions),
            processing_ms=processing_ms,
            degraded=False,
            request_id=result.request_id,
        )
        if webhook:
            url = _console_url(config["region"], config["reports_bucket"], key)
            slack_formatter.post_to_slack(
                webhook, slack_formatter.format_brief(brief, final_sev, bundle, report_url=url)
            )
        _emit_metrics(config, processing_ms, result.usage, failed=False)
        logger.info("Triaged %s -> %s in %dms", finding_id, final_sev, processing_ms)
        return {"status": "analyzed", "finding_id": finding_id, "final_severity": final_sev}

    # Degraded path.
    final_sev = severity_scorer.rescore(gd_sev, blast, related_count, "LOW")
    report_obj = {
        "finding": bundle["finding"],
        "enrichment": bundle,
        "brief": None,
        "degraded": True,
        "reason": degraded_reason,
        "final_severity": final_sev,
    }
    key = report.persist_report(
        config["reports_bucket"], finding_id, report_obj, s3_client=boto3.client("s3")
    )
    report.write_audit(
        config["audit_table"],
        finding_id,
        ddb_resource=boto3.resource("dynamodb"),
        final_severity=final_sev,
        blast_radius=blast,
        action_count=0,
        processing_ms=processing_ms,
        degraded=True,
        request_id=result.request_id,
        reason=degraded_reason,
    )
    if webhook:
        slack_formatter.post_to_slack(
            webhook, degraded.format_degraded(bundle, degraded_reason or "unknown")
        )
    _emit_metrics(config, processing_ms, result.usage, failed=True)
    logger.warning("Degraded triage for %s (reason=%s)", finding_id, degraded_reason)
    return {"status": "degraded", "finding_id": finding_id, "reason": degraded_reason}


def lambda_handler(event: dict, context=None) -> dict:
    """EventBridge entrypoint. The finding is in event['detail'] for GuardDuty events."""
    finding = event.get("detail") if isinstance(event, dict) and "detail" in event else event
    return process(finding)
