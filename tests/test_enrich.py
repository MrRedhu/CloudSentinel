"""Tests for finding parsing and the enrich() aggregator."""

from __future__ import annotations

import json
from datetime import datetime

import boto3
from moto import mock_aws

from enrichment import enrich, parse_finding

ASSUME = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
    }
)


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


class _FakeGuardDuty:
    def list_findings(self, **_kwargs):
        return {"FindingIds": []}

    def get_findings(self, **_kwargs):
        return {"Findings": []}


def test_parse_finding(gd_finding, consts):
    parsed = parse_finding(gd_finding)
    assert parsed["finding_id"] == gd_finding["Id"]
    assert parsed["access_key_id"] == consts.ACCESS_KEY
    assert parsed["user_type"] == "AssumedRole"
    assert parsed["user_name"] == "app-server-role"
    assert parsed["principal_id"].startswith("AROA")
    assert isinstance(parsed["center_time"], datetime)
    # center_time uses Service.EventLastSeen (14:20).
    assert parsed["center_time"].hour == 14 and parsed["center_time"].minute == 20


def test_enrich_assembles_bundle(gd_finding):
    detail = {
        "eventName": "GetSecretValue",
        "eventSource": "secretsmanager.amazonaws.com",
        "sourceIPAddress": "203.0.113.9",
    }
    ct_pages = [
        {
            "Events": [
                {
                    "EventId": "e1",
                    "EventName": "GetSecretValue",
                    "EventTime": datetime(2026, 6, 18, 14, 15),
                    "CloudTrailEvent": json.dumps(detail),
                }
            ]
        }
    ]

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(RoleName="app-server-role", AssumeRolePolicyDocument=ASSUME)
        admin_arn = iam.create_policy(PolicyName="AdministratorAccess", PolicyDocument=_DOC)[
            "Policy"
        ]["Arn"]
        iam.attach_role_policy(RoleName="app-server-role", PolicyArn=admin_arn)

        bundle = enrich(
            gd_finding,
            detector_id="det-123",
            clients={
                "cloudtrail": _FakeCloudTrail(ct_pages),
                "iam": iam,
                "guardduty": _FakeGuardDuty(),
            },
        )

    assert bundle["finding"]["id"] == gd_finding["Id"]
    assert bundle["finding"]["principal"]["user_name"] == "app-server-role"
    assert bundle["cloudtrail_events"][0]["eventName"] == "GetSecretValue"
    assert bundle["iam_context"]["blast_radius"] == "CRITICAL"
    assert bundle["related_findings"] == {"count": 0, "summaries": []}
    assert bundle["access_key_id"] is not None
