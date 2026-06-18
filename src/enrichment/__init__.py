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


def _g(d: dict, *keys):
    """Get the first present key. GuardDuty uses PascalCase via the GetFindings
    API (Id, Resource, ...) but camelCase via EventBridge (id, resource, ...);
    we support both so the same parser works for the Lambda trigger and the CLI.
    """
    for key in keys:
        if key in d:
            return d[key]
    return None


def parse_finding(finding: dict) -> dict:
    """Extract the fields we need from a GuardDuty finding (either casing)."""
    resource = _g(finding, "Resource", "resource") or {}
    access = _g(resource, "AccessKeyDetails", "accessKeyDetails") or {}
    instance = _g(resource, "InstanceDetails", "instanceDetails") or {}
    service = _g(finding, "Service", "service") or {}

    center = (
        _g(service, "EventLastSeen", "eventLastSeen")
        or _g(finding, "UpdatedAt", "updatedAt")
        or _g(service, "EventFirstSeen", "eventFirstSeen")
        or _g(finding, "CreatedAt", "createdAt")
    )

    return {
        "finding_id": _g(finding, "Id", "id"),
        "type": _g(finding, "Type", "type"),
        "severity": _g(finding, "Severity", "severity"),
        "title": _g(finding, "Title", "title"),
        "region": _g(finding, "Region", "region"),
        "resource_type": _g(resource, "ResourceType", "resourceType"),
        "access_key_id": _g(access, "AccessKeyId", "accessKeyId"),
        "principal_id": _g(access, "PrincipalId", "principalId"),
        "user_type": _g(access, "UserType", "userType"),
        "user_name": _g(access, "UserName", "userName"),
        "instance_id": _g(instance, "InstanceId", "instanceId"),
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
