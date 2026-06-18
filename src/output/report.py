"""Persist the full report to S3 and an audit row to DynamoDB.

S3 holds the complete artifact (finding + enrichment + brief) for later review;
DynamoDB holds a compact, queryable audit record per triage. Both are keyed on
finding_id; the audit table adds an ISO timestamp sort key so re-triage of the
same finding appends rather than overwrites.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def persist_report(
    bucket: str, finding_id: str, report: dict, *, s3_client, timestamp: str | None = None
) -> str:
    """Write the full report JSON to S3. Returns the object key."""
    timestamp = timestamp or _now_iso()
    key = f"reports/{finding_id}/{timestamp}.json"
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(report, default=str, indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    return key


def write_audit(
    table_name: str,
    finding_id: str,
    *,
    ddb_resource,
    final_severity: str,
    blast_radius: str,
    action_count: int,
    processing_ms: int,
    degraded: bool,
    request_id: str | None = None,
    reason: str | None = None,
    timestamp: str | None = None,
) -> str:
    """Write one audit row. Returns the timestamp used as the sort key."""
    timestamp = timestamp or _now_iso()
    item = {
        "finding_id": finding_id,
        "timestamp": timestamp,
        "final_severity": final_severity,
        "blast_radius": blast_radius,
        "action_count": action_count,
        "processing_ms": Decimal(str(processing_ms)),  # DynamoDB has no int/float, uses Decimal
        "degraded": degraded,
    }
    if request_id:
        item["request_id"] = request_id
    if reason:
        item["reason"] = reason
    ddb_resource.Table(table_name).put_item(Item=item)
    return timestamp
