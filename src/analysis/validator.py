"""Post-generation validation and grounding of the model's brief.

Structured outputs guarantee the JSON *shape* is valid, but not that its
*content* is true. Two ways a model can still go wrong, both defended here:

1. Invented MITRE technique IDs (e.g. ``T9999``). We reject any ``technique_id``
   not in the shared allowlist.
2. Hallucinated resources — naming an S3 bucket or ARN that never appears in the
   evidence. We drop any ``affected_resources`` entry that does not literally
   occur in the enrichment bundle (grounding).

The result reports what was dropped (for the audit trail) and whether the output
is trustworthy enough to ship. If a model returned techniques but every one was
invalid, that signals it ignored the constraints — the handler should retry once,
then fall back to degraded mode.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from analysis.attack import is_valid_technique
from analysis.schema import IncidentBrief


@dataclass
class ValidationResult:
    brief: IncidentBrief
    ok: bool
    dropped_techniques: list[str] = field(default_factory=list)
    dropped_resources: list[str] = field(default_factory=list)


def _evidence_text(enrichment: dict) -> str:
    """Flatten the enrichment bundle into one searchable string."""
    return json.dumps(enrichment, default=str, ensure_ascii=False)


def validate_and_ground(brief: IncidentBrief, enrichment: dict) -> ValidationResult:
    """Return a cleaned brief plus what was rejected and whether it's trustworthy."""
    haystack = _evidence_text(enrichment)

    kept_techniques = []
    dropped_techniques: list[str] = []
    for tech in brief.attack_techniques:
        if is_valid_technique(tech.technique_id):
            kept_techniques.append(tech)
        else:
            dropped_techniques.append(tech.technique_id)

    kept_resources = []
    dropped_resources: list[str] = []
    for resource in brief.affected_resources:
        candidate = resource.strip()
        if candidate and candidate in haystack:
            kept_resources.append(resource)
        else:
            dropped_resources.append(resource)

    cleaned = brief.model_copy(
        update={
            "attack_techniques": kept_techniques,
            "affected_resources": kept_resources,
        }
    )

    # Trustworthy unless the model proposed techniques and ALL were invalid —
    # that means it ignored the allowlist, so the rest is suspect too.
    all_techniques_invalid = bool(brief.attack_techniques) and not kept_techniques
    ok = not all_techniques_invalid

    return ValidationResult(
        brief=cleaned,
        ok=ok,
        dropped_techniques=dropped_techniques,
        dropped_resources=dropped_resources,
    )
