"""The structured-output contract: ``IncidentBrief``.

This schema is what Claude is constrained to produce via the Anthropic
structured-outputs feature (``messages.parse(output_format=IncidentBrief)``).

Design constraints driven by the API (see plan / claude-api skill):
- Every object sets ``extra="forbid"`` so the generated JSON Schema carries
  ``additionalProperties: false`` (required by structured outputs).
- The schema is intentionally FLAT: strings, enums, and arrays of simple
  objects. No recursion, no numeric (`ge`/`le`) or string-length constraints —
  structured outputs reject those (the SDK silently strips them, so relying on
  them would be a false sense of safety). All hard validation lives in
  ``analysis.validator`` instead, where we control it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["low", "medium", "high"]


class Technique(BaseModel):
    """A single MITRE ATT&CK technique the model attributes to the activity."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str  # e.g. "T1078.004" — validated against the allowlist later
    name: str
    rationale: str  # one sentence grounding the attribution in the evidence


class IncidentBrief(BaseModel):
    """The analyst-ready incident brief produced from a GuardDuty finding."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    severity: Severity
    confidence: Confidence
    attack_techniques: list[Technique]
    affected_resources: list[str]  # ARNs / ids / bucket names — grounded later
    recommended_actions: list[str]
