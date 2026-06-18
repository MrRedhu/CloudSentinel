"""Enrichment aggregator: a GuardDuty finding -> a rich context bundle.

``enrich(finding)`` parses the finding, then gathers CloudTrail activity, the
implicated principal's IAM blast radius, and related findings into the single
dict the sanitizer + analysis layers consume. Every sub-lookup is best-effort —
a failure in one source degrades that section rather than failing the triage.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import boto3

from enrichment import cloudtrail, guardduty, iam_context

logger = logging.getLogger("cloudsentinel.enrichment")


def _parse_time(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


def parse_finding(finding: dict) -> dict:
    """Extract the fields we need from a GuardDuty finding (GetFindings schema)."""
    resource = finding.get("Resource", {})
    access = resource.get("AccessKeyDetails", {})
    instance = resource.get("InstanceDetails", {})
    service = finding.get("Service", {})

    center = (
        service.get("EventLastSeen")
        or finding.get("UpdatedAt")
        or service.get("EventFirstSeen")
        or finding.get("CreatedAt")
    )

    return {
        "finding_id": finding.get("Id"),
        "type": finding.get("Type"),
        "severity": finding.get("Severity"),
        "title": finding.get("Title"),
        "region": finding.get("Region"),
        "resource_type": resource.get("ResourceType"),
        "access_key_id": access.get("AccessKeyId"),
        "principal_id": access.get("PrincipalId"),
        "user_type": access.get("UserType"),
        "user_name": access.get("UserName"),
        "instance_id": instance.get("InstanceId"),
        "center_time": _parse_time(center),
    }


def _clients(clients: dict | None) -> dict:
    clients = clients or {}
    return {
        "cloudtrail": clients.get("cloudtrail") or boto3.client("cloudtrail"),
        "iam": clients.get("iam") or boto3.client("iam"),
        "guardduty": clients.get("guardduty") or boto3.client("guardduty"),
    }


def enrich(finding: dict, *, detector_id: str | None = None, clients: dict | None = None) -> dict:
    """Turn a GuardDuty finding into a full enrichment bundle."""
    parsed = parse_finding(finding)
    c = _clients(clients)

    events = cloudtrail.pull_events(
        parsed["access_key_id"], parsed["center_time"], client=c["cloudtrail"]
    )
    iam = iam_context.profile(parsed["user_type"], parsed["user_name"], client=c["iam"])
    related = guardduty.related(
        detector_id,
        principal_id=parsed["principal_id"],
        exclude_finding_id=parsed["finding_id"],
        client=c["guardduty"],
    )

    return {
        "finding": {
            "id": parsed["finding_id"],
            "type": parsed["type"],
            "severity": parsed["severity"],
            "title": parsed["title"],
            "region": parsed["region"],
            "resource_type": parsed["resource_type"],
            "principal": {
                "user_type": parsed["user_type"],
                "user_name": parsed["user_name"],
                "principal_id": parsed["principal_id"],
            },
            "time": parsed["center_time"].isoformat(),
        },
        "cloudtrail_events": events,
        "iam_context": iam,
        "related_findings": related,
        "access_key_id": parsed["access_key_id"],
        "instance_id": parsed["instance_id"],
    }
