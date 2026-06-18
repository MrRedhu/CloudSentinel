# Sample Output

Real output captured from the deployed system (Opus 4.8, AWS sandbox). Nothing
here is hand-edited.

## 1. Incident brief (instance-credential exfiltration)

**Input** — a GuardDuty finding: type
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, severity
`8.0`, principal `app-server-role`, access key `AKIAIOSFODNN7EXAMPLE`, instance
`i-0abc123def4567890`.

**Output** — the validated `IncidentBrief` (delivered to Slack, stored in S3):

```
HIGH  ·  confidence: medium
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS

Summary
  GuardDuty reports that temporary credentials for the EC2 instance role
  app-server-role (instance i-0abc123def4567890) were used from an IP address
  outside AWS, the classic signature of stolen instance-role credentials being
  exploited off the instance. The associated access key is AKIAIOSFODNN7EXAMPLE.
  No CloudTrail activity was provided and the IAM blast radius is UNKNOWN, so the
  attacker's follow-on actions and the role's actual permissions cannot be
  confirmed from this evidence — confidence is reduced accordingly, but the
  finding type itself is a strong indicator of compromise.

MITRE ATT&CK
  T1552.005  Unsecured Credentials: Cloud Instance Metadata API
  T1078.004  Valid Accounts: Cloud Accounts

Recommended actions
  1. Revoke active sessions for role app-server-role (apply an
     AWSRevokeOlderSessions-style deny policy) to invalidate the exfiltrated
     temporary credentials.
  2. Pull CloudTrail for the principal and access key AKIAIOSFODNN7EXAMPLE to
     identify the external source IP and any API calls made off-instance.
  3. Determine the IAM permissions actually attached to app-server-role to
     establish the true blast radius, since the provided context lists it UNKNOWN.
  4. Isolate or inspect instance i-0abc123def4567890 for signs of compromise and
     rotate any secrets the role could access.
  5. Check other regions and accounts for follow-on activity tied to the same
     credentials.

[~16.6 s | in 438 / out 1150 tokens | system prompt cached: 7460 tokens]
```

Note the **honest confidence calibration**: with no CloudTrail and an UNKNOWN
blast radius, the model lowered confidence to `medium` and said so explicitly,
rather than inventing detail.

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
