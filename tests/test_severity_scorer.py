"""Tests for deterministic severity re-scoring."""

from __future__ import annotations

import pytest

from analysis.severity_scorer import rescore


@pytest.mark.parametrize(
    "gd, blast, related, model, expected",
    [
        # GuardDuty high + high blast, model slightly lower -> stays HIGH.
        (8.0, "HIGH", 0, "MEDIUM", "HIGH"),
        # CRITICAL blast radius dominates even a low GuardDuty score.
        (2.0, "CRITICAL", 0, "LOW", "CRITICAL"),
        # All-low -> LOW.
        (3.0, "LOW", 0, "LOW", "LOW"),
        # Medium GD + corroborating related finding bumps to HIGH.
        (5.0, "LOW", 2, "LOW", "HIGH"),
        # High signals + many related findings escalate to CRITICAL.
        (9.0, "MEDIUM", 5, "HIGH", "CRITICAL"),
        # Model rates higher than the heuristics -> we honor the higher.
        (3.0, "LOW", 0, "HIGH", "HIGH"),
    ],
)
def test_rescore(gd, blast, related, model, expected):
    assert rescore(gd, blast, related, model) == expected


def test_severity_never_below_hard_signals():
    # Even if the model says LOW, a HIGH blast radius keeps it at least HIGH.
    assert rescore(7.0, "HIGH", 0, "LOW") == "HIGH"


def test_unknown_strings_default_low():
    # Defensive: unrecognized inputs must not crash and default conservatively.
    assert rescore(0.0, "unknown", 0, "???") == "LOW"
