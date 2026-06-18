"""Tests for related-findings lookup (faked GuardDuty client)."""

from __future__ import annotations

from enrichment.guardduty import related


class _FakeGuardDuty:
    def __init__(self, finding_ids, findings):
        self._ids = finding_ids
        self._findings = findings
        self.get_findings_called_with = None

    def list_findings(self, **_kwargs):
        return {"FindingIds": self._ids}

    def get_findings(self, **kwargs):
        self.get_findings_called_with = kwargs.get("FindingIds")
        return {"Findings": self._findings}


def test_no_detector_or_principal_returns_empty():
    assert related(None, principal_id="p") == {"count": 0, "summaries": []}
    assert related("det", principal_id=None) == {"count": 0, "summaries": []}


def test_excludes_current_and_summarizes():
    fake = _FakeGuardDuty(
        finding_ids=["cur", "other-1", "other-2"],
        findings=[
            {"Id": "other-1", "Type": "Recon:IAMUser/X", "Severity": 5.0, "Title": "t1"},
            {"Id": "other-2", "Type": "Stealth:IAMUser/Y", "Severity": 7.0, "Title": "t2"},
        ],
    )
    result = related("det", principal_id="p", exclude_finding_id="cur", client=fake)

    assert result["count"] == 2  # "cur" excluded
    assert "cur" not in fake.get_findings_called_with
    assert {s["id"] for s in result["summaries"]} == {"other-1", "other-2"}


def test_api_failure_is_swallowed():
    class Boom:
        def list_findings(self, **_):
            raise RuntimeError("boom")

    assert related("det", principal_id="p", client=Boom()) == {"count": 0, "summaries": []}
