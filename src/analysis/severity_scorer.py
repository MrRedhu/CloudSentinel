"""Deterministic severity re-scoring.

The model proposes a severity, but we don't take it on faith. The final severity
combines four signals deterministically so the result is explainable and
reproducible (important for the eval harness and for defending a number to a
reviewer):

- GuardDuty's own numeric severity (0-10; >= 7 is "high" per AWS).
- The IAM blast radius of the implicated principal (LOW..CRITICAL).
- The count of related findings for the same principal (corroboration).
- The model's proposed severity (it sees nuance the heuristics don't).

We take the strongest of the band signals, then bump for corroboration, and let
a CRITICAL blast radius dominate. The point is that severity is never *lower*
than what the hard signals justify, even if the model underrates it.
"""

from __future__ import annotations

_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_LEVEL_NUM = {name: i + 1 for i, name in enumerate(_LEVELS)}


def _gd_band(gd_severity: float) -> int:
    """Map GuardDuty's 0-10 severity to a 1-4 band."""
    if gd_severity >= 7.0:
        return _LEVEL_NUM["HIGH"]
    if gd_severity >= 4.0:
        return _LEVEL_NUM["MEDIUM"]
    return _LEVEL_NUM["LOW"]


def _level_num(value: str, default: int = 1) -> int:
    return _LEVEL_NUM.get(value.upper(), default)


def rescore(
    gd_severity: float,
    blast_radius: str,
    related_count: int,
    model_severity: str,
) -> str:
    """Combine the signals into a final LOW/MEDIUM/HIGH/CRITICAL severity."""
    blast_num = _level_num(blast_radius)
    model_num = _level_num(model_severity)

    score = max(_gd_band(gd_severity), blast_num, model_num)

    # Corroborating related findings nudge severity up (capped).
    if related_count >= 3:
        score += 1
    elif related_count >= 1 and score < _LEVEL_NUM["HIGH"]:
        score += 1

    # A principal that can do anything (admin / *:*) dominates.
    if blast_num >= _LEVEL_NUM["CRITICAL"]:
        score = _LEVEL_NUM["CRITICAL"]

    score = max(1, min(score, len(_LEVELS)))
    return _LEVELS[score - 1]
