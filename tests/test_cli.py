"""Tests for the CLI (pipeline mocked, no AWS/network)."""

from __future__ import annotations

import json

from click.testing import CliRunner

import cloudsentinel
from analysis.claude_client import AnalysisResult

BUNDLE = {
    "finding": {
        "id": "finding-123",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.0,
        "principal": {"user_name": "app-server-role"},
    },
    "iam_context": {"blast_radius": "HIGH"},
    "related_findings": {"count": 1},
    "cloudtrail_events": [{"eventName": "GetSecretValue"}],
}


def test_analyze_file_prints_brief(monkeypatch, tmp_path, brief_factory):
    finding_file = tmp_path / "finding.json"
    finding_file.write_text(json.dumps({"Id": "finding-123"}), encoding="utf-8")

    brief = brief_factory(severity="HIGH", techniques=[("T1552.005", "IMDS theft")], resources=[])
    analysis = AnalysisResult(
        brief=brief, degraded=False, usage={"input_tokens": 400, "output_tokens": 200},
        request_id="req_x",
    )
    monkeypatch.setattr(cloudsentinel, "enrich", lambda finding, detector_id=None: BUNDLE)
    monkeypatch.setattr(cloudsentinel.claude_client, "analyze", lambda bundle: analysis)

    result = CliRunner().invoke(cloudsentinel.cli, ["analyze", "--file", str(finding_file)])

    assert result.exit_code == 0, result.output
    assert "HIGH" in result.output
    assert brief.summary in result.output
    assert "T1552.005" in result.output
    assert "1." in result.output  # numbered action


def test_analyze_degraded(monkeypatch, tmp_path):
    finding_file = tmp_path / "finding.json"
    finding_file.write_text(json.dumps({"Id": "finding-123"}), encoding="utf-8")

    analysis = AnalysisResult(brief=None, degraded=True, reason="refusal")
    monkeypatch.setattr(cloudsentinel, "enrich", lambda finding, detector_id=None: BUNDLE)
    monkeypatch.setattr(cloudsentinel.claude_client, "analyze", lambda bundle: analysis)

    result = CliRunner().invoke(cloudsentinel.cli, ["analyze", "--file", str(finding_file)])
    assert result.exit_code == 0, result.output
    assert "unavailable" in result.output.lower()
    assert "refusal" in result.output


def test_analyze_requires_source():
    result = CliRunner().invoke(cloudsentinel.cli, ["analyze"])
    assert result.exit_code != 0
    assert "Provide --finding-id or --file" in result.output
