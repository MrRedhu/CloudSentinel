"""Render an IncidentBrief as a Slack Block Kit message and post it.

Posting uses urllib (no extra runtime dependency — the Lambda artifact stays
small). Formatting is kept pure (returns a dict) so it can be unit-tested without
touching the network.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger("cloudsentinel.output.slack")

SEVERITY_EMOJI = {
    "LOW": ":large_blue_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "HIGH": ":large_orange_circle:",
    "CRITICAL": ":red_circle:",
}


def _header(final_severity: str, finding: dict) -> dict:
    emoji = SEVERITY_EMOJI.get(final_severity, ":white_circle:")
    ftype = finding.get("type") or "GuardDuty finding"
    text = f"{emoji} {final_severity} — {ftype}"
    return {"type": "header", "text": {"type": "plain_text", "text": text[:150], "emoji": True}}


def _fields_section(brief, final_severity: str, enrichment: dict) -> dict:
    finding = enrichment["finding"]
    blast = enrichment.get("iam_context", {}).get("blast_radius", "UNKNOWN")
    related = enrichment.get("related_findings", {}).get("count", 0)
    principal = finding.get("principal", {})
    principal_str = principal.get("user_name") or "unknown"
    fields = [
        f"*Final severity:*\n{final_severity}",
        f"*Confidence:*\n{brief.confidence}",
        f"*IAM blast radius:*\n{blast}",
        f"*GuardDuty severity:*\n{finding.get('severity')}",
        f"*Principal:*\n{principal_str}",
        f"*Related findings:*\n{related}",
    ]
    return {"type": "section", "fields": [{"type": "mrkdwn", "text": f} for f in fields]}


def format_brief(
    brief, final_severity: str, enrichment: dict, report_url: str | None = None
) -> dict:
    """Build the Slack message payload for a completed incident brief."""
    finding = enrichment["finding"]
    blocks: list[dict] = [_header(final_severity, finding)]

    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": brief.summary}})
    blocks.append(_fields_section(brief, final_severity, enrichment))

    if brief.attack_techniques:
        tags = "  ".join(f"`{t.technique_id}` {t.name}" for t in brief.attack_techniques)
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{tags}"}}
        )

    if brief.recommended_actions:
        numbered = "\n".join(f"{i}. {a}" for i, a in enumerate(brief.recommended_actions, 1))
        actions_text = f"*Recommended actions:*\n{numbered}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": actions_text}})

    context_parts = [f"finding `{finding.get('id')}`"]
    if report_url:
        context_parts.append(f"<{report_url}|full report>")
    blocks.append(
        {"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(context_parts)}]}
    )

    return {"blocks": blocks}


def post_to_slack(webhook_url: str, payload: dict, *, timeout: float = 10.0) -> bool:
    """POST a Block Kit payload to a Slack incoming webhook. Returns success."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed webhook URL
            return 200 <= resp.status < 300
    except urllib.error.URLError as exc:
        logger.warning("Slack post failed: %s", exc)
        return False
