"""Tests for S3 report persistence and DynamoDB audit rows (moto)."""

from __future__ import annotations

import json
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

from output.report import persist_report, write_audit

BUCKET = "cloudsentinel-reports-test"
AUDIT_TABLE = "cloudsentinel-audit"


@pytest.fixture
def aws():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[
                {"AttributeName": "finding_id", "KeyType": "HASH"},
                {"AttributeName": "timestamp", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "finding_id", "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield {"s3": s3, "ddb": ddb}


def test_persist_report_writes_json(aws):
    report = {"finding": {"id": "f1"}, "brief": {"severity": "HIGH"}}
    key = persist_report(BUCKET, "f1", report, s3_client=aws["s3"], timestamp="2026-06-18T00:00:00")

    assert key == "reports/f1/2026-06-18T00:00:00.json"
    body = aws["s3"].get_object(Bucket=BUCKET, Key=key)["Body"].read()
    assert json.loads(body)["brief"]["severity"] == "HIGH"


def test_write_audit_row(aws):
    ts = write_audit(
        AUDIT_TABLE,
        "f1",
        ddb_resource=aws["ddb"],
        final_severity="CRITICAL",
        blast_radius="HIGH",
        action_count=3,
        processing_ms=4200,
        degraded=False,
        request_id="req_abc",
        timestamp="2026-06-18T00:00:00",
    )

    item = aws["ddb"].Table(AUDIT_TABLE).get_item(
        Key={"finding_id": "f1", "timestamp": ts}
    )["Item"]
    assert item["final_severity"] == "CRITICAL"
    assert item["processing_ms"] == Decimal("4200")
    assert item["degraded"] is False
    assert item["request_id"] == "req_abc"
