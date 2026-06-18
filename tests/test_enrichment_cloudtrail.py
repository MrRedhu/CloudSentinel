"""Tests for CloudTrail event pulling (faked client)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from enrichment.cloudtrail import pull_events

NOW = datetime(2026, 6, 18, 14, 10, tzinfo=UTC)


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        return iter(self._pages)


class _FakeCloudTrail:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, _name):
        return _FakePaginator(self._pages)


def _event(event_id, name, ip, *, error=None, minute=10):
    detail = {"eventName": name, "eventSource": "s3.amazonaws.com", "sourceIPAddress": ip,
              "userAgent": "aws-cli/2.0", "awsRegion": "us-east-1"}
    if error:
        detail["errorCode"] = error
    return {
        "EventId": event_id,
        "EventName": name,
        "EventTime": datetime(2026, 6, 18, 14, minute, tzinfo=UTC),
        "Username": "app-server-role",
        "CloudTrailEvent": json.dumps(detail),
    }


def test_no_access_key_returns_empty():
    assert pull_events(None, NOW, client=_FakeCloudTrail([])) == []


def test_flatten_dedupe_and_sort():
    pages = [
        {"Events": [_event("e2", "ListBuckets", "203.0.113.5", minute=12)]},
        {"Events": [
            _event("e1", "GetObject", "203.0.113.5", error="AccessDenied", minute=8),
            _event("e2", "ListBuckets", "203.0.113.5", minute=12),  # duplicate id
        ]},
    ]
    events = pull_events("AKIA...", NOW, client=_FakeCloudTrail(pages))

    assert [e["eventName"] for e in events] == ["GetObject", "ListBuckets"]  # sorted by time
    assert events[0]["sourceIPAddress"] == "203.0.113.5"
    assert events[0]["errorCode"] == "AccessDenied"


def test_max_events_cap():
    events_list = [_event(f"e{i}", "GetObject", "203.0.113.5", minute=i % 60) for i in range(10)]
    pages = [{"Events": events_list}]
    events = pull_events("AKIA...", NOW, client=_FakeCloudTrail(pages), max_events=3)
    assert len(events) == 3
