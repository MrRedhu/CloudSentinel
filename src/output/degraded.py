"""Degraded-mode Slack message: deliver raw context when Claude is unavailable.

If the model refuses, errors, or returns nothing usable, CloudSentinel must not
go dark — an analyst still needs the enriched context. This formats the raw
enrichment (blast radius, CloudTrail summary, related findings) into a Slack
message clearly flagged as un-analyzed, so a human can triage immediately.
"""

from __future__ import annotations


def _distinct(values) -> list[str]:
    seen: list[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return seen


def format_degraded(enrichment: dict, reason: str) -> dict:
    """Build the Slack payload for the degraded (no-AI) path."""
    finding = enrichment["finding"]
    events = enrichment.get("cloudtrail_events", [])
    blast = enrichment.get("iam_context", {}).get("blast_radius", "UNKNOWN")
    related = enrichment.get("related_findings", {}).get("count", 0)
    principal = finding.get("principal", {}).get("user_name") or "unknown"

    event_names = _distinct(e.get("eventName") for e in events)[:10]
    source_ips = _distinct(e.get("sourceIPAddress") for e in events)[:5]

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":warning: AI analysis unavailable — manual triage needed",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"CloudSentinel could not produce an AI brief (reason: `{reason}`). "
                    "Raw enriched context below for manual triage."
                ),
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Finding:*\n{finding.get('type')}"},
                {"type": "mrkdwn", "text": f"*GuardDuty severity:*\n{finding.get('severity')}"},
                {"type": "mrkdwn", "text": f"*IAM blast radius:*\n{blast}"},
                {"type": "mrkdwn", "text": f"*Related findings:*\n{related}"},
                {"type": "mrkdwn", "text": f"*CloudTrail events:*\n{len(events)}"},
                {"type": "mrkdwn", "text": f"*Principal:*\n{principal}"},
            ],
        },
    ]

    if event_names:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Recent API calls:* {', '.join(event_names)}\n"
                        f"*Source IPs:* {', '.join(source_ips) or 'n/a'}"
                    ),
                },
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"finding `{finding.get('id')}`"}],
        }
    )
    return {"blocks": blocks}
