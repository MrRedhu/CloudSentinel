"""Tests for the degraded-mode Slack formatter."""

from __future__ import annotations

from output.degraded import format_degraded


def _bundle():
    return {
        "finding": {
            "id": "finding-123",
            "type": "Stealth:IAMUser/CloudTrailLoggingDisabled",
            "severity": 7.0,
            "principal": {"user_name": "ci-deploy"},
        },
        "iam_context": {"blast_radius": "MEDIUM"},
        "related_findings": {"count": 1},
        "cloudtrail_events": [
            {"eventName": "StopLogging", "sourceIPAddress": "203.0.113.7"},
            {"eventName": "DescribeTrails", "sourceIPAddress": "203.0.113.7"},
        ],
    }


def test_degraded_message_flags_unavailable_and_shows_context():
    payload = format_degraded(_bundle(), "refusal")
    blob = repr(payload)

    assert "AI analysis unavailable" in payload["blocks"][0]["text"]["text"]
    assert "refusal" in blob
    assert "MEDIUM" in blob  # blast radius surfaced
    assert "StopLogging" in blob  # recent API calls surfaced
    assert "203.0.113.7" in blob  # source IP surfaced
    assert "finding-123" in blob


def test_degraded_handles_no_events():
    bundle = _bundle()
    bundle["cloudtrail_events"] = []
    payload = format_degraded(bundle, "api_error:APIConnectionError")
    blob = repr(payload)
    assert "AI analysis unavailable" in blob
    assert "api_error" in blob
