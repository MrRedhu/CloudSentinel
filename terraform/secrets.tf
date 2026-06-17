# Secret CONTAINERS only. The actual values are injected out-of-band via the CLI
# so they never touch Terraform state:
#   aws secretsmanager put-secret-value --secret-id cloudsentinel/anthropic-api-key --secret-string 'sk-ant-...'
#   aws secretsmanager put-secret-value --secret-id cloudsentinel/slack-webhook    --secret-string 'https://hooks.slack.com/...'

resource "aws_secretsmanager_secret" "anthropic" {
  name        = var.anthropic_secret_name
  description = "Anthropic API key for CloudSentinel (value set via CLI, not Terraform)."
}

resource "aws_secretsmanager_secret" "slack" {
  name        = var.slack_secret_name
  description = "Slack incoming-webhook URL for CloudSentinel (value set via CLI, not Terraform)."
}
