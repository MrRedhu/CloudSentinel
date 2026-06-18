"""Shared pytest fixtures.

The enrichment fixture is *synthetic but realistic* — it mirrors the shape that
``enrichment.enrich()`` will produce in Stage B, with groundable resource
identifiers (a role ARN, bucket, secret ARN, instance id, access key) so the
validator's grounding logic has something true to anchor on. Stage B will add
real Stratus-derived findings under ``tests/sample_findings/`` and reuse these
same tests against them.
"""

from __future__ import annotations

import types

import pytest

from analysis.schema import IncidentBrief, Technique

# Groundable identifiers that appear in the enrichment fixture below.
ROLE_ARN = "arn:aws:iam::123456789012:role/app-server-role"
BUCKET = "cloudsentinel-demo-data"
SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-credentials-AbCdEf"
INSTANCE_ID = "i-0abc123def4567890"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    """Dummy AWS creds + region so boto3/moto never touch real credentials."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


@pytest.fixture
def consts() -> types.SimpleNamespace:
    """Groundable identifiers that appear in the ``enrichment`` fixture."""
    return types.SimpleNamespace(
        ROLE_ARN=ROLE_ARN,
        BUCKET=BUCKET,
        SECRET_ARN=SECRET_ARN,
        INSTANCE_ID=INSTANCE_ID,
        ACCESS_KEY=ACCESS_KEY,
    )


@pytest.fixture
def enrichment() -> dict:
    """A realistic enriched-finding bundle (instance-credential exfiltration)."""
    return {
        "finding": {
            "id": "2a1b3c4d5e6f7890abcdef1234567890",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "severity": 8.0,
            "title": "Credentials for the EC2 instance role were used from an external IP.",
            "principal_arn": ROLE_ARN,
            "region": "us-east-1",
        },
        "cloudtrail_events": [
            {
                "eventName": "GetCallerIdentity",
                "eventSource": "sts.amazonaws.com",
                "sourceIPAddress": "203.0.113.42",
                "userAgent": "aws-cli/2.15.0",
            },
            {
                "eventName": "ListBuckets",
                "eventSource": "s3.amazonaws.com",
                "sourceIPAddress": "203.0.113.42",
                "userAgent": "aws-cli/2.15.0",
            },
            {
                "eventName": "GetSecretValue",
                "eventSource": "secretsmanager.amazonaws.com",
                "sourceIPAddress": "203.0.113.42",
                "requestParameters": {"secretId": SECRET_ARN},
            },
            {
                "eventName": "GetObject",
                "eventSource": "s3.amazonaws.com",
                "sourceIPAddress": "203.0.113.42",
                "requestParameters": {"bucketName": BUCKET},
            },
        ],
        "iam_context": {
            "arn": ROLE_ARN,
            "attached_policies": ["SecretsManagerReadWrite", "AmazonS3ReadOnlyAccess"],
            "inline_policies": [],
            "groups": [],
            "blast_radius": "HIGH",
        },
        "related_findings": {"count": 0, "summaries": []},
        "access_key_id": ACCESS_KEY,
        "instance_id": INSTANCE_ID,
    }


@pytest.fixture
def gd_finding() -> dict:
    """A GuardDuty finding (GetFindings schema): instance-credential exfiltration."""
    return {
        "Id": "2a1b3c4d5e6f7890abcdef1234567890",
        "Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "Severity": 8.0,
        "Title": "Credentials for the EC2 instance role were used from an external IP.",
        "Region": "us-east-1",
        "Resource": {
            "ResourceType": "AccessKey",
            "AccessKeyDetails": {
                "AccessKeyId": ACCESS_KEY,
                "PrincipalId": "AROAEXAMPLEPRINCIPAL:i-0abc123def4567890",
                "UserType": "AssumedRole",
                "UserName": "app-server-role",
            },
        },
        "Service": {
            "EventFirstSeen": "2026-06-18T14:00:00.000Z",
            "EventLastSeen": "2026-06-18T14:20:00.000Z",
        },
        "CreatedAt": "2026-06-18T14:05:00.000Z",
        "UpdatedAt": "2026-06-18T14:21:00.000Z",
    }


@pytest.fixture
def brief_factory():
    """Factory to build IncidentBrief instances for validator/client tests."""

    def _make(
        *,
        severity: str = "HIGH",
        confidence: str = "high",
        techniques: list[tuple[str, str]] | None = None,
        resources: list[str] | None = None,
        actions: list[str] | None = None,
    ) -> IncidentBrief:
        techniques = techniques if techniques is not None else [("T1552.005", "IMDS theft")]
        return IncidentBrief(
            summary="Synthetic brief for tests.",
            severity=severity,
            confidence=confidence,
            attack_techniques=[
                Technique(technique_id=tid, name=name, rationale="test") for tid, name in techniques
            ],
            affected_resources=resources if resources is not None else [ROLE_ARN],
            recommended_actions=actions if actions is not None else ["Investigate."],
        )

    return _make
