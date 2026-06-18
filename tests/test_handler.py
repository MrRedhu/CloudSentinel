"""Orchestration tests for handler.process (AWS/network boundaries mocked)."""

from __future__ import annotations

import types

import handler
from analysis.claude_client import AnalysisResult

CONFIG = {
    "dedup_table": "d",
    "audit_table": "a",
    "reports_bucket": "b",
    "detector_id": "det",
    "slack_secret_id": "s",
    "metrics_namespace": "CloudSentinel",
    "region": "us-east-1",
}

BUNDLE = {
    "finding": {
        "id": "finding-123",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.0,
        "principal": {"user_name": "app-server-role"},
    },
    "iam_context": {"blast_radius": "HIGH"},
    "related_findings": {"count": 0},
    "cloudtrail_events": [],
}

FINDING = {"Id": "finding-123"}


def _patch(monkeypatch, *, claim=True, analysis=None):
    captured = {}
    monkeypatch.setattr(handler, "_config", lambda: CONFIG)
    monkeypatch.setattr(
        handler, "DedupStore", lambda name: types.SimpleNamespace(claim=lambda fid: claim)
    )
    monkeypatch.setattr(handler, "enrich", lambda finding, detector_id=None: BUNDLE)
    monkeypatch.setattr(handler.claude_client, "analyze", lambda bundle: analysis)
    monkeypatch.setattr(handler, "get_slack_webhook", lambda sid: None)
    monkeypatch.setattr(handler.report, "persist_report", lambda *a, **k: "reports/x.json")

    def _audit(*a, **k):
        captured["audit"] = k
        return "ts"

    monkeypatch.setattr(handler.report, "write_audit", _audit)
    monkeypatch.setattr(handler.metrics, "emit", lambda *a, **k: None)
    return captured


def test_happy_path_analyzes_and_persists(monkeypatch, brief_factory):
    brief = brief_factory(severity="HIGH", techniques=[("T1552.005", "IMDS theft")], resources=[])
    analysis = AnalysisResult(
        brief=brief, degraded=False, usage={"input_tokens": 100, "output_tokens": 50},
        request_id="req1",
    )
    captured = _patch(monkeypatch, claim=True, analysis=analysis)

    result = handler.process(FINDING, config=CONFIG)

    assert result["status"] == "analyzed"
    assert result["final_severity"] == "HIGH"
    assert captured["audit"]["degraded"] is False
    assert captured["audit"]["request_id"] == "req1"


def test_degraded_path_on_refusal(monkeypatch):
    analysis = AnalysisResult(brief=None, degraded=True, reason="refusal")
    captured = _patch(monkeypatch, claim=True, analysis=analysis)

    result = handler.process(FINDING, config=CONFIG)

    assert result["status"] == "degraded"
    assert result["reason"] == "refusal"
    assert captured["audit"]["degraded"] is True
    assert captured["audit"]["reason"] == "refusal"


def test_dedup_skip(monkeypatch):
    _patch(monkeypatch, claim=False, analysis=None)
    result = handler.process(FINDING, config=CONFIG)
    assert result["status"] == "skipped"
    assert result["reason"] == "already_triaged"


def test_no_finding_id(monkeypatch):
    _patch(monkeypatch, claim=True, analysis=None)
    result = handler.process({}, config=CONFIG)
    assert result["status"] == "skipped"
    assert result["reason"] == "no_finding_id"


def test_lambda_handler_unwraps_eventbridge_detail(monkeypatch):
    analysis = AnalysisResult(brief=None, degraded=True, reason="refusal")
    _patch(monkeypatch, claim=True, analysis=analysis)
    result = handler.lambda_handler({"detail": FINDING})
    assert result["finding_id"] == "finding-123"
