# Sample Output

Real output captured from the deployed system (Opus 4.8, AWS sandbox). Nothing
here is hand-edited.

## 1. Real attack — Stratus Red Team instance-credential theft

A genuine finding from detonating
[`aws.credential-access.ec2-steal-instance-credentials`](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/):
Stratus stole the instance role's IMDS credentials and used them from outside AWS.
Because the role and CloudTrail trail were live, enrichment was **rich** — real
CloudTrail events and a computed blast radius (IPs/keys redacted below).

**Output** — the validated `IncidentBrief`:

```
HIGH  ·  confidence: high
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
blast radius: LOW   ·   cloudtrail: 2 events

Summary
  Temporary credentials (ASIA…REDACTED) for the EC2 instance role
  stratus-red-team-ec2-steal-credentials-role, attached to instance
  i-010771724cfa4afd3, were used from an external IP (198.51.100.23) outside AWS
  to call sts:GetCallerIdentity and ec2:DescribeInstances. The user agent on every
  call is 'stratus-red-team', the signature of the open-source Stratus Red Team
  attack-simulation tool, and the role name itself references credential theft,
  strongly suggesting this is an authorized red-team exercise rather than a live
  intrusion. The blast radius is LOW (the role only carries
  AmazonSSMManagedInstanceCore plus an inline policy), and post-exfiltration
  activity was limited to read-only discovery with no privilege escalation or data
  access. Treat as suspicious and confirm with the security team whether the
  exercise was sanctioned.

MITRE ATT&CK
  T1552.005  Unsecured Credentials: Cloud Instance Metadata API
  T1078.004  Valid Accounts: Cloud Accounts
  T1580      Cloud Infrastructure Discovery

Recommended actions
  1. Confirm with the security/red-team team whether a Stratus Red Team exercise
     targeting stratus-red-team-ec2-steal-credentials-role was authorized.
  2. Review CloudTrail for all activity from the access key and source IP to
     confirm only read-only discovery occurred and no escalation followed.
  3. If not sanctioned, revoke the role's active sessions and quarantine instance
     i-010771724cfa4afd3 for forensic review.
  4. Verify IMDSv2 is enforced on i-010771724cfa4afd3 to reduce future
     instance-credential theft risk.

[~27 s | in 866 / out 1768 tokens]
```

What makes this impressive: enrichment pulled the **real CloudTrail events** and
computed a **real LOW blast radius** from the role's actual policies, so the model
gave **high** confidence — and it correctly recognized the `stratus-red-team` user
agent as an attack-simulation tool and contextualized the activity as a likely
authorized exercise, without dropping its guard ("confirm it was sanctioned").

## 1b. Sample finding — honest calibration on thin evidence

On a finding with no CloudTrail and an UNKNOWN blast radius, the model lowers
confidence to `medium` and says so explicitly rather than inventing detail —
e.g. *"No CloudTrail activity was provided and the IAM blast radius is UNKNOWN, so
the attacker's follow-on actions cannot be confirmed — confidence is reduced
accordingly, but the finding type itself is a strong indicator of compromise."*

## 2. The model resists being fooled

Run against a GuardDuty **sample** finding (placeholder principals), the model
detected it and refused to overreact — making "confirm this isn't a sample
finding" the first action and dropping confidence to `low`:

```
confidence: low
Summary
  ... the placeholder names (GeneratedFinding*, i-99999999) strongly suggest this
  is a GuardDuty sample/test finding: there are no CloudTrail events, the IAM
  blast radius is UNKNOWN, and no related findings exist, so the real-world impact
  cannot be confirmed.

Recommended actions
  1. Confirm whether this is a GuardDuty sample finding (the GeneratedFinding* and
     i-99999999 placeholders indicate test data) before initiating live response.
  ...
```

## 3. Evaluation harness

`python eval/harness.py` over 8 labeled findings:

```
finding                          expected  model     final     match       ms
--------------------------------------------------------------------------------
01_instance_cred_exfil           HIGH      HIGH      HIGH      OK       16557
02_cloudtrail_disabled           HIGH      HIGH      HIGH      OK       14445
03_crypto_mining                 HIGH      HIGH      HIGH      OK       10399
04_backdoor_cc                   HIGH      HIGH      HIGH      OK       15781
05_malicious_ip_caller           MEDIUM    MEDIUM    MEDIUM    OK       12050
06_anomalous_discovery           MEDIUM    MEDIUM    MEDIUM    OK       12665
07_recon_portscan                LOW       LOW       LOW       OK        7573
08_root_cred_usage               LOW       MEDIUM    MEDIUM    MISS     12494
--------------------------------------------------------------------------------
severity-match accuracy: 7/8 = 88%
mean time-to-triage:     12745 ms
```

The single miss is a defensible disagreement: the model rated root-credential
usage `MEDIUM` against a `LOW` label — arguably the more correct call, since root
usage genuinely warrants attention.

## 4. Degraded path

When Claude is unavailable (refusal, API error, or unreadable key), the analyst
still gets the raw context, flagged as un-analyzed:

```
:warning:  AI analysis unavailable — manual triage needed
CloudSentinel could not produce an AI brief (reason: api_error:APIConnectionError).
Finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
GuardDuty severity: 8.0   IAM blast radius: HIGH   Related findings: 1
Recent API calls: GetCallerIdentity, ListBuckets, GetSecretValue, GetObject
```
