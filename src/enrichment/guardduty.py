"""Find other GuardDuty findings for the same principal.

A single finding is easier to dismiss than the same principal showing up three
times in a week. Related findings are corroboration — the severity re-scorer
uses their count, and the analyst sees the pattern.
"""

from __future__ import annotations

import logging

import boto3

logger = logging.getLogger("cloudsentinel.enrichment.guardduty")

MAX_SUMMARIES = 10


def related(
    detector_id: str | None,
    *,
    principal_id: str | None = None,
    exclude_finding_id: str | None = None,
    client=None,
    max_summaries: int = MAX_SUMMARIES,
) -> dict:
    """Return count + brief summaries of other findings for ``principal_id``."""
    if not detector_id or not principal_id:
        return {"count": 0, "summaries": []}

    client = client or boto3.client("guardduty")
    try:
        listed = client.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "resource.accessKeyDetails.principalId": {"Eq": [principal_id]},
                }
            },
        )
        ids = [fid for fid in listed.get("FindingIds", []) if fid != exclude_finding_id]
        if not ids:
            return {"count": 0, "summaries": []}

        detail = client.get_findings(DetectorId=detector_id, FindingIds=ids[:max_summaries])
        summaries = [
            {
                "id": f.get("Id"),
                "type": f.get("Type"),
                "severity": f.get("Severity"),
                "title": f.get("Title"),
            }
            for f in detail.get("Findings", [])
        ]
        return {"count": len(ids), "summaries": summaries}
    except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
        logger.warning("Related-findings lookup failed: %s", exc)
        return {"count": 0, "summaries": []}
