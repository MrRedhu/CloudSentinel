"""Tests for technique-allowlist validation and resource grounding."""

from __future__ import annotations

from analysis.validator import validate_and_ground

HALLUCINATED_BUCKET = "s3://totally-made-up-bucket-xyz"


def test_invalid_technique_is_dropped(enrichment, brief_factory, consts):
    brief = brief_factory(
        techniques=[("T1552.005", "IMDS theft"), ("T9999", "Made up")],
        resources=[consts.ROLE_ARN],
    )
    result = validate_and_ground(brief, enrichment)

    kept_ids = [t.technique_id for t in result.brief.attack_techniques]
    assert kept_ids == ["T1552.005"]
    assert result.dropped_techniques == ["T9999"]
    assert result.ok is True  # at least one valid technique remains


def test_hallucinated_resource_is_dropped(enrichment, brief_factory, consts):
    brief = brief_factory(
        techniques=[("T1530", "Data from Cloud Storage")],
        resources=[consts.BUCKET, HALLUCINATED_BUCKET],
    )
    result = validate_and_ground(brief, enrichment)

    assert consts.BUCKET in result.brief.affected_resources
    assert HALLUCINATED_BUCKET not in result.brief.affected_resources
    assert HALLUCINATED_BUCKET in result.dropped_resources


def test_all_invalid_techniques_flags_not_ok(enrichment, brief_factory):
    brief = brief_factory(techniques=[("T9999", "Made up"), ("T0000", "Also fake")])
    result = validate_and_ground(brief, enrichment)

    assert result.brief.attack_techniques == []
    assert result.ok is False  # model ignored the allowlist -> retry/degrade


def test_empty_techniques_is_ok(enrichment, brief_factory):
    brief = brief_factory(techniques=[])
    result = validate_and_ground(brief, enrichment)
    assert result.ok is True  # nothing mapped is acceptable
