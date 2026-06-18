"""Tests for the evaluation harness pure logic (no Claude calls)."""

from __future__ import annotations

import harness

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_load_labeled_findings():
    items = harness.load_labeled()
    assert len(items) >= 8
    for _name, finding, expected in items:
        assert expected in VALID_SEVERITIES
        assert finding.get("Id")
        assert finding.get("Type")
        assert finding.get("Severity") is not None


def test_summarize_computes_accuracy_and_mean():
    results = [
        {"match": True, "ms": 100},
        {"match": True, "ms": 200},
        {"match": False, "ms": 300},
        {"match": True, "ms": 400},
    ]
    s = harness.summarize(results)
    assert s["count"] == 4
    assert s["matches"] == 3
    assert s["accuracy"] == 0.75
    assert s["mean_ms"] == 250


def test_summarize_empty():
    s = harness.summarize([])
    assert s["count"] == 0
    assert s["accuracy"] == 0.0
    assert s["mean_ms"] == 0
