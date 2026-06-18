"""Tests for IAM profiling + blast-radius scoring (moto-mocked IAM).

We attach *customer-managed* policies with well-known names (AdministratorAccess,
AmazonS3ReadOnlyAccess) rather than the real AWS-managed ARNs, because moto does
not ship an attachable managed-policy catalog. The blast-radius classifier keys
on the policy name, so this exercises exactly the same code path.
"""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from enrichment.iam_context import profile

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

_ANY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
    }
)

_WILDCARD_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
)


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")


def _managed(iam, name: str) -> str:
    return iam.create_policy(PolicyName=name, PolicyDocument=_ANY_DOC)["Policy"]["Arn"]


def test_admin_managed_policy_is_critical(iam):
    iam.create_role(RoleName="admin-role", AssumeRolePolicyDocument=ASSUME)
    iam.attach_role_policy(RoleName="admin-role", PolicyArn=_managed(iam, "AdministratorAccess"))
    result = profile("AssumedRole", "admin-role", client=iam)
    assert result["blast_radius"] == "CRITICAL"
    assert "AdministratorAccess" in result["attached_policies"]


def test_wildcard_inline_policy_is_critical(iam):
    iam.create_role(RoleName="wild-role", AssumeRolePolicyDocument=ASSUME)
    iam.put_role_policy(RoleName="wild-role", PolicyName="all", PolicyDocument=_WILDCARD_DOC)
    assert profile("AssumedRole", "wild-role", client=iam)["blast_radius"] == "CRITICAL"


def test_read_only_managed_policy_is_medium(iam):
    iam.create_user(UserName="ro-user")
    iam.attach_user_policy(UserName="ro-user", PolicyArn=_managed(iam, "AmazonS3ReadOnlyAccess"))
    assert profile("IAMUser", "ro-user", client=iam)["blast_radius"] == "MEDIUM"


def test_scoped_inline_policy_is_low(iam):
    iam.create_role(RoleName="scoped-role", AssumeRolePolicyDocument=ASSUME)
    iam.put_role_policy(
        RoleName="scoped-role",
        PolicyName="scoped",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::specific-bucket/*",
                    }
                ],
            }
        ),
    )
    assert profile("AssumedRole", "scoped-role", client=iam)["blast_radius"] == "LOW"


def test_missing_principal_is_unknown(iam):
    assert profile("AssumedRole", "does-not-exist", client=iam)["blast_radius"] == "UNKNOWN"
    assert profile("AssumedRole", None, client=iam)["blast_radius"] == "UNKNOWN"
