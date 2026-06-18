"""Pull the CloudTrail activity around a finding's principal.

GuardDuty tells you *that* something happened; CloudTrail tells you the *story* —
what API calls the implicated credential made, from where, and whether they
errored. We look up events by AccessKeyId (a first-class CloudTrail lookup
attribute and the most reliable join key from a GuardDuty finding), within a
window around the finding, then flatten each event to the few fields that matter
for triage.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import boto3

logger = logging.getLogger("cloudsentinel.enrichment.cloudtrail")

DEFAULT_WINDOW_HOURS = 2
MAX_EVENTS = 200


def _flatten(event: dict) -> dict:
    """Reduce a CloudTrail lookup event to triage-relevant fields."""
    detail = {}
    raw = event.get("CloudTrailEvent")
    if raw:
        try:
            detail = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            detail = {}

    event_time = event.get("EventTime")
    if isinstance(event_time, datetime):
        event_time = event_time.isoformat()
    else:
        event_time = str(event_time)
    return {
        "eventName": event.get("EventName") or detail.get("eventName"),
        "eventSource": detail.get("eventSource"),
        "eventTime": event_time,
        "username": event.get("Username") or detail.get("userIdentity", {}).get("userName"),
        "sourceIPAddress": detail.get("sourceIPAddress"),
        "userAgent": detail.get("userAgent"),
        "awsRegion": detail.get("awsRegion"),
        "errorCode": detail.get("errorCode"),
        "errorMessage": detail.get("errorMessage"),
        "requestParameters": detail.get("requestParameters"),
    }


def pull_events(
    access_key_id: str | None,
    center_time: datetime,
    *,
    client=None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    max_events: int = MAX_EVENTS,
) -> list[dict]:
    """Return up to ``max_events`` CloudTrail events for ``access_key_id``.

    Events are looked up in a +/- ``window_hours`` window around ``center_time``,
    de-duplicated by EventId, and sorted oldest-first.
    """
    if not access_key_id:
        return []

    client = client or boto3.client("cloudtrail")
    if center_time.tzinfo is None:
        center_time = center_time.replace(tzinfo=UTC)
    start = center_time - timedelta(hours=window_hours)
    end = center_time + timedelta(hours=window_hours)

    seen: set[str] = set()
    flattened: list[dict] = []
    paginator = client.get_paginator("lookup_events")
    pages = paginator.paginate(
        LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
        StartTime=start,
        EndTime=end,
    )
    try:
        for page in pages:
            for event in page.get("Events", []):
                event_id = event.get("EventId")
                if event_id in seen:
                    continue
                seen.add(event_id)
                flattened.append(_flatten(event))
                if len(flattened) >= max_events:
                    flattened.sort(key=lambda e: e.get("eventTime") or "")
                    return flattened
    except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
        logger.warning("CloudTrail lookup failed: %s", exc)

    flattened.sort(key=lambda e: e.get("eventTime") or "")
    return flattened
