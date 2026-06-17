"""Tests for the DynamoDB-backed dedup gate (moto-mocked)."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from security.dedup import TTL_ATTRIBUTE, DedupStore

TABLE = "cloudsentinel-dedup"


@pytest.fixture
def table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield TABLE


def test_claim_is_atomic_first_wins(table):
    store = DedupStore(table)
    assert store.claim("finding-1") is True
    assert store.claim("finding-1") is False  # already claimed
    assert store.claim("finding-2") is True  # different finding


def test_already_triaged_reflects_state(table):
    store = DedupStore(table)
    assert store.already_triaged("finding-x") is False
    store.claim("finding-x")
    assert store.already_triaged("finding-x") is True


def test_mark_triaged_writes_ttl(table):
    store = DedupStore(table)
    store.mark_triaged("finding-y", ttl_seconds=3600)
    item = boto3.resource("dynamodb", region_name="us-east-1").Table(table).get_item(
        Key={"finding_id": "finding-y"}
    )["Item"]
    assert TTL_ATTRIBUTE in item
    assert int(item[TTL_ATTRIBUTE]) > 0
