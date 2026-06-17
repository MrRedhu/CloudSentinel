"""Idempotency / dedup gate backed by DynamoDB.

GuardDuty can re-emit the same finding (EventBridge is at-least-once, and a
finding's severity can be updated, re-firing the rule). Without a gate, every
re-fire pays for another Claude analysis and spams Slack. This module records
which finding IDs we've already triaged, with a TTL so the table self-prunes.

The race-safe primitive is :meth:`DedupStore.claim`, a conditional put: the
first invocation for a finding wins and returns ``True``; concurrent or later
invocations get ``False`` and should stop. ``already_triaged`` / ``mark_triaged``
are also provided for callers that want the two steps separately.
"""

from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 days
# Must match the TTL attribute configured on the table in terraform/dynamodb.tf.
TTL_ATTRIBUTE = "expires_at"


class DedupStore:
    """Thin wrapper over a DynamoDB dedup table keyed on ``finding_id``."""

    def __init__(self, table_name: str, *, dynamodb_resource=None, region_name: str | None = None):
        resource = dynamodb_resource or boto3.resource("dynamodb", region_name=region_name)
        self._table = resource.Table(table_name)

    def claim(self, finding_id: str, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> bool:
        """Atomically claim a finding for triage.

        Returns ``True`` if this call is the first to claim ``finding_id`` (the
        caller should proceed), ``False`` if it was already claimed (skip).
        """
        expires_at = int(time.time()) + ttl_seconds
        try:
            self._table.put_item(
                Item={"finding_id": finding_id, TTL_ATTRIBUTE: expires_at},
                ConditionExpression="attribute_not_exists(finding_id)",
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def already_triaged(self, finding_id: str) -> bool:
        """Return whether ``finding_id`` has an active dedup record."""
        resp = self._table.get_item(Key={"finding_id": finding_id})
        return "Item" in resp

    def mark_triaged(self, finding_id: str, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        """Unconditionally record ``finding_id`` as triaged (overwrites)."""
        expires_at = int(time.time()) + ttl_seconds
        self._table.put_item(Item={"finding_id": finding_id, TTL_ATTRIBUTE: expires_at})
