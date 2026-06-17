# ---------------------------------------------------------------------------
# Lambda execution role — least privilege, READ + NOTIFY only.
#
# Design point (cited in DESIGN_DECISIONS): CloudSentinel can read enough to
# triage and can notify humans, but it has NO ability to change infrastructure.
# There are deliberately no iam:* writes, no ec2 stop/terminate, no s3 delete,
# no guardduty mutation — the blast radius of a compromised analyzer is bounded
# to "read telemetry and post a Slack message".
# ---------------------------------------------------------------------------

locals {
  function_name = "${local.name_prefix}-triage"
  log_group_arn = "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.function_name}:*"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name_prefix}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_permissions" {
  # CloudWatch Logs for the function only.
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [local.log_group_arn, "${local.log_group_arn}:*"]
  }

  # GuardDuty: read findings on our detector only.
  statement {
    sid       = "GuardDutyRead"
    actions   = ["guardduty:GetFindings", "guardduty:ListFindings", "guardduty:GetDetector"]
    resources = [aws_guardduty_detector.main.arn]
  }

  # CloudTrail LookupEvents has no resource-level permissions (must be "*").
  statement {
    sid       = "CloudTrailLookup"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  # IAM read-only, to profile the implicated principal and compute blast radius.
  # Read actions only — no create/update/delete/attach. "*" is required because
  # attached policies include AWS-managed policy ARNs (arn:aws:iam::aws:policy/*).
  statement {
    sid = "IamReadOnly"
    actions = [
      "iam:GetUser",
      "iam:GetRole",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListRolePolicies",
      "iam:ListUserPolicies",
      "iam:GetRolePolicy",
      "iam:GetUserPolicy",
      "iam:ListGroupsForUser",
    ]
    resources = ["*"]
  }

  # DynamoDB: only our two tables.
  statement {
    sid       = "DynamoDb"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.dedup.arn, aws_dynamodb_table.audit.arn]
  }

  # S3: write reports to our bucket only.
  statement {
    sid       = "S3PutReport"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }

  # SNS: publish to our alerts topic only.
  statement {
    sid       = "SnsPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  # Secrets Manager: read only the two secrets we own.
  statement {
    sid       = "SecretsRead"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.anthropic.arn, aws_secretsmanager_secret.slack.arn]
  }

  # CloudWatch custom metrics, scoped to our namespace.
  statement {
    sid       = "Metrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudSentinel"]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.name_prefix}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}
