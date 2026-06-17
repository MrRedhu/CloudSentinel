"""MITRE ATT&CK technique allowlist (single source of truth).

Both the system prompt (as a reference table the model may cite from) and the
validator (as a hard allowlist) import this. Keeping one canonical mapping means
the model is never told about a technique the validator would reject, and the
validator can never silently drift from what the prompt advertises.

Scope: techniques realistically observable from AWS GuardDuty findings +
CloudTrail telemetry. This is intentionally a curated subset of ATT&CK, not the
full matrix — a tight allowlist is a feature, not a limitation (it bounds what
the model can claim and makes hallucinated IDs trivial to reject).
"""

from __future__ import annotations

# technique_id -> human-readable name. IDs follow MITRE ATT&CK (Txxxx[.yyy]).
ATTACK_TECHNIQUES: dict[str, str] = {
    # Initial Access
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1199": "Trusted Relationship",
    # Execution
    "T1059": "Command and Scripting Interpreter",
    "T1651": "Cloud Administration Command",
    # Persistence
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1136": "Create Account",
    "T1136.003": "Create Account: Cloud Account",
    "T1525": "Implant Internal Image",
    # Privilege Escalation
    "T1548": "Abuse Elevation Control Mechanism",
    "T1484": "Domain or Tenant Policy Modification",
    # Defense Evasion
    "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1578.001": "Modify Cloud Compute Infrastructure: Create Snapshot",
    "T1578.002": "Modify Cloud Compute Infrastructure: Create Cloud Instance",
    "T1578.003": "Modify Cloud Compute Infrastructure: Delete Cloud Instance",
    "T1535": "Unused/Unsupported Cloud Regions",
    "T1070": "Indicator Removal",
    "T1070.008": "Indicator Removal: Clear Mailbox Data",
    # Credential Access
    "T1552": "Unsecured Credentials",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1555": "Credentials from Password Stores",
    "T1528": "Steal Application Access Token",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    # Discovery
    "T1580": "Cloud Infrastructure Discovery",
    "T1538": "Cloud Service Dashboard",
    "T1526": "Cloud Service Discovery",
    "T1087": "Account Discovery",
    "T1087.004": "Account Discovery: Cloud Account",
    "T1069": "Permission Groups Discovery",
    "T1069.003": "Permission Groups Discovery: Cloud Groups",
    "T1518": "Software Discovery",
    "T1046": "Network Service Discovery",
    # Lateral Movement
    "T1021": "Remote Services",
    "T1550": "Use Alternate Authentication Material",
    "T1550.001": "Use Alternate Authentication Material: Application Access Token",
    # Collection
    "T1530": "Data from Cloud Storage",
    "T1213": "Data from Information Repositories",
    # Exfiltration
    "T1537": "Transfer Data to Cloud Account",
    "T1567": "Exfiltration Over Web Service",
    "T1048": "Exfiltration Over Alternative Protocol",
    # Impact
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1496": "Resource Hijacking",
    "T1531": "Account Access Removal",
    "T1490": "Inhibit System Recovery",
}


# One-line descriptions, surfaced in the system prompt so the model has enough
# context to attribute techniques accurately (and to keep the prompt above the
# Opus 4.8 prompt-cache floor). Every key in ATTACK_TECHNIQUES has an entry.
ATTACK_DESCRIPTIONS: dict[str, str] = {
    "T1078": "Use of legitimate credentials to access and blend in.",
    "T1078.004": "Use of valid cloud (IAM/SSO) credentials from an unexpected source.",
    "T1190": "Exploiting a public-facing app/service to gain access.",
    "T1199": "Abusing a trusted third party / cross-account relationship.",
    "T1059": "Running commands or scripts on a host or service.",
    "T1651": "Running commands on instances via cloud APIs (e.g. SSM RunCommand).",
    "T1098": "Modifying accounts to maintain or elevate access.",
    "T1098.001": "Adding access keys / credentials to an existing principal.",
    "T1098.003": "Attaching additional roles/policies to gain permissions.",
    "T1136": "Creating a new account for persistence.",
    "T1136.003": "Creating a new cloud (IAM) user/account for persistence.",
    "T1525": "Implanting a malicious machine image for persistence.",
    "T1548": "Bypassing or abusing elevation controls to gain privileges.",
    "T1484": "Altering org/tenant policy (SCPs, IAM policy) to weaken controls.",
    "T1562": "Weakening or disabling security defenses.",
    "T1562.001": "Disabling or modifying security tools/agents.",
    "T1562.008": "Disabling or tampering with cloud logging (CloudTrail/GuardDuty).",
    "T1578": "Manipulating cloud compute infrastructure via control-plane APIs.",
    "T1578.001": "Creating a snapshot to copy/exfiltrate a volume.",
    "T1578.002": "Spinning up instances (often for mining or staging).",
    "T1578.003": "Deleting instances to destroy or hide activity.",
    "T1535": "Operating in unused regions to evade monitoring.",
    "T1070": "Removing or altering indicators of the intrusion.",
    "T1070.008": "Clearing mailbox/data artifacts to hide activity.",
    "T1552": "Harvesting credentials left unsecured in the environment.",
    "T1552.005": "Stealing instance credentials via the metadata API (IMDS).",
    "T1555": "Extracting credentials from stores/secret managers.",
    "T1528": "Stealing an application or cloud access token.",
    "T1110": "Guessing or spraying credentials at scale.",
    "T1110.001": "Guessing passwords for a known account.",
    "T1110.003": "Spraying a few passwords across many accounts.",
    "T1580": "Enumerating cloud infrastructure (instances, volumes, networks).",
    "T1538": "Browsing the cloud console/dashboard for recon.",
    "T1526": "Enumerating which cloud services exist/are enabled.",
    "T1087": "Enumerating accounts/users in the environment.",
    "T1087.004": "Enumerating cloud (IAM) users, roles, and policies.",
    "T1069": "Discovering permission groups and their members.",
    "T1069.003": "Enumerating cloud groups and role memberships.",
    "T1518": "Discovering installed software/services.",
    "T1046": "Scanning for reachable network services.",
    "T1021": "Moving laterally via remote services.",
    "T1550": "Authenticating with stolen tokens/keys instead of passwords.",
    "T1550.001": "Reusing a stolen application access token to authenticate.",
    "T1530": "Reading data directly from cloud storage (e.g. S3).",
    "T1213": "Pulling data from information repositories/wikis.",
    "T1537": "Exfiltrating by transferring to an attacker cloud account.",
    "T1567": "Exfiltrating over a legitimate web service.",
    "T1048": "Exfiltrating over an alternate/unmonitored protocol.",
    "T1485": "Destroying data to cause impact.",
    "T1486": "Encrypting data for extortion (ransomware).",
    "T1496": "Hijacking resources for the attacker's gain (e.g. crypto mining).",
    "T1531": "Removing access to lock out legitimate users.",
    "T1490": "Inhibiting recovery (deleting snapshots/backups).",
}


def is_valid_technique(technique_id: str) -> bool:
    """True if ``technique_id`` is in the allowlist (exact match)."""
    return technique_id in ATTACK_TECHNIQUES


def technique_name(technique_id: str) -> str | None:
    """Canonical name for a technique ID, or None if unknown."""
    return ATTACK_TECHNIQUES.get(technique_id)
