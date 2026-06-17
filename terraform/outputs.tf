output "guardduty_detector_id" {
  description = "GuardDuty detector id (used by the CLI / enrichment)."
  value       = aws_guardduty_detector.main.id
}

output "lambda_function_name" {
  description = "Name of the triage Lambda."
  value       = aws_lambda_function.triage.function_name
}

output "reports_bucket" {
  description = "S3 bucket holding full incident-brief JSON."
  value       = aws_s3_bucket.reports.bucket
}

output "alerts_topic_arn" {
  description = "SNS topic ARN for alerts."
  value       = aws_sns_topic.alerts.arn
}

output "dedup_table" {
  value = aws_dynamodb_table.dedup.name
}

output "audit_table" {
  value = aws_dynamodb_table.audit.name
}

output "anthropic_secret_name" {
  description = "Set the value with: aws secretsmanager put-secret-value --secret-id <name> --secret-string 'sk-ant-...'"
  value       = aws_secretsmanager_secret.anthropic.name
}

output "slack_secret_name" {
  description = "Set the value with: aws secretsmanager put-secret-value --secret-id <name> --secret-string 'https://hooks.slack.com/...'"
  value       = aws_secretsmanager_secret.slack.name
}
