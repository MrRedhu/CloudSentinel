"""Profile the implicated IAM principal and score its blast radius.

The same GuardDuty finding is far more dangerous against a principal that can
assume admin or read every secret than against a tightly-scoped one. We pull the
principal's attached + inline policies (and group memberships, for users) and
reduce them to a single blast-radius band the analyst and the severity re-scorer
can reason about.

Blast radius is a *heuristic*, deliberately conservative: it classifies by
well-known managed-policy names and scans inline policy documents for wildcard
grants. It is not a full IAM policy evaluation — it's a fast "how bad could this
principal be" signal.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import unquote

import boto3

logger = logging.getLogger("cloudsentinel.enrichment.iam")

_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Managed-policy name -> blast-radius contribution.
_CRITICAL_POLICIES = {"AdministratorAccess"}
_HIGH_POLICIES = {
    "IAMFullAccess",
    "PowerUserAccess",
    "SecretsManagerReadWrite",
    "AdministratorAccess-Amplify",
}


def _max_band(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


def _classify_managed(name: str) -> str:
    if name in _CRITICAL_POLICIES:
        return "CRITICAL"
    if name in _HIGH_POLICIES or name.endswith("FullAccess"):
        return "HIGH"
    if "SecretsManager" in name or "KeyManagementService" in name:
        return "HIGH"
    if name.endswith("ReadOnlyAccess") or name in {"SecurityAudit", "ViewOnlyAccess"}:
        return "MEDIUM"
    return "LOW"


def _normalize_doc(document) -> dict:
    """Inline policy docs come back as a dict (moto) or URL-encoded JSON (AWS)."""
    if isinstance(document, str):
        try:
            return json.loads(unquote(document))
        except (ValueError, TypeError):
            return {}
    return document if isinstance(document, dict) else {}


def _doc_band(document) -> str:
    """Scan an inline policy document for broad wildcard grants."""
    document = _normalize_doc(document)
    band = "LOW"
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = stmt.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        has_star_resource = "*" in resources
        if "*" in actions and has_star_resource:
            return "CRITICAL"  # full admin
        for action in actions:
            if action.endswith(":*") and has_star_resource:
                band = _max_band(band, "HIGH")
            elif ("secretsmanager" in action.lower() or "iam:" in action.lower()):
                band = _max_band(band, "HIGH")
    return band


def profile(user_type: str | None, user_name: str | None, *, client=None) -> dict:
    """Return a profile + blast radius for an IAM role or user.

    ``user_type`` follows GuardDuty's AccessKeyDetails.UserType
    ("IAMUser", "AssumedRole", "Role", ...). Best-effort: any API failure
    degrades to an empty profile with blast_radius UNKNOWN rather than raising.
    """
    client = client or boto3.client("iam")
    is_user = (user_type or "").lower() == "iamuser"

    attached: list[str] = []
    inline: list[str] = []
    groups: list[str] = []
    band = "LOW"

    if not user_name:
        return {
            "user_type": user_type,
            "user_name": user_name,
            "attached_policies": [],
            "inline_policies": [],
            "groups": [],
            "blast_radius": "UNKNOWN",
        }

    try:
        if is_user:
            attached = [
                p["PolicyName"]
                for p in client.list_attached_user_policies(UserName=user_name).get(
                    "AttachedPolicies", []
                )
            ]
            inline = client.list_user_policies(UserName=user_name).get("PolicyNames", [])
            for name in inline:
                doc = client.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"]
                band = _max_band(band, _doc_band(doc))
            groups = [
                g["GroupName"]
                for g in client.list_groups_for_user(UserName=user_name).get("Groups", [])
            ]
        else:
            attached = [
                p["PolicyName"]
                for p in client.list_attached_role_policies(RoleName=user_name).get(
                    "AttachedPolicies", []
                )
            ]
            inline = client.list_role_policies(RoleName=user_name).get("PolicyNames", [])
            for name in inline:
                doc = client.get_role_policy(RoleName=user_name, PolicyName=name)["PolicyDocument"]
                band = _max_band(band, _doc_band(doc))
    except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
        logger.warning("IAM profile lookup failed for %s: %s", user_name, exc)
        return {
            "user_type": user_type,
            "user_name": user_name,
            "attached_policies": attached,
            "inline_policies": inline,
            "groups": groups,
            "blast_radius": "UNKNOWN",
        }

    for name in attached:
        band = _max_band(band, _classify_managed(name))

    return {
        "user_type": user_type,
        "user_name": user_name,
        "attached_policies": attached,
        "inline_policies": inline,
        "groups": groups,
        "blast_radius": band,
    }
