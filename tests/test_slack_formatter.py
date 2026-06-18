"""Tests for Slack Block Kit formatting and posting."""

from __future__ import annotations

import urllib.error

from output import slack_formatter


def _bundle():
    """enrich()-shaped context bundle."""
    return {
        "finding": {
            "id": "finding-123",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "severity": 8.0,
            "principal": {"user_name": "app-server-role"},
        },
        "iam_context": {"blast_radius": "HIGH"},
        "related_findings": {"count": 2},
        "cloudtrail_events": [],
    }


def _blocks_text(payload):
    return repr(payload)


def test_format_brief_has_all_sections(brief_factory):
    brief = brief_factory(
        severity="HIGH",
        techniques=[("T1552.005", "IMDS theft")],
        resources=["arn:aws:iam::123456789012:role/app-server-role"],
        actions=["Revoke the role's sessions.", "Rotate exposed secrets."],
    )
    payload = slack_formatter.format_brief(
        brief, "CRITICAL", _bundle(), report_url="https://s3/report.json"
    )
    blob = _blocks_text(payload)

    assert payload["blocks"][0]["type"] == "header"
    assert "CRITICAL" in payload["blocks"][0]["text"]["text"]
    assert brief.summary in blob
    assert "T1552.005" in blob
    assert "1. Revoke the role's sessions." in blob
    assert "finding-123" in blob
    assert "full report" in blob


def test_format_brief_handles_empty_techniques_and_actions(brief_factory):
    brief = brief_factory(techniques=[], actions=[])
    payload = slack_formatter.format_brief(brief, "LOW", _bundle())
    blob = _blocks_text(payload)
    assert "MITRE ATT&CK" not in blob
    assert "Recommended actions" not in blob
    # No report link when report_url is omitted.
    assert "full report" not in blob


def test_post_to_slack_success(monkeypatch):
    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(slack_formatter.urllib.request, "urlopen", lambda *a, **k: _Resp())
    assert slack_formatter.post_to_slack("https://hooks.slack.com/x", {"blocks": []}) is True


def test_post_to_slack_failure(monkeypatch):
    def _boom(*a, **k):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(slack_formatter.urllib.request, "urlopen", _boom)
    assert slack_formatter.post_to_slack("https://hooks.slack.com/x", {"blocks": []}) is False
