variable "region" {
  description = "AWS region to deploy into. GuardDuty + findings are region-scoped."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for all resources."
  type        = string
  default     = "cloudsentinel"
}

variable "anthropic_secret_name" {
  description = "Secrets Manager name holding the Anthropic API key (value injected via CLI, never Terraform)."
  type        = string
  default     = "cloudsentinel/anthropic-api-key"
}

variable "slack_secret_name" {
  description = "Secrets Manager name holding the Slack incoming-webhook URL (value injected via CLI)."
  type        = string
  default     = "cloudsentinel/slack-webhook"
}

variable "alert_email" {
  description = "Optional email to subscribe to the SNS alerts topic. Empty = no subscription."
  type        = string
  default     = ""
}

variable "severity_threshold" {
  description = "Minimum GuardDuty finding severity (0-10) that triggers analysis."
  type        = number
  default     = 7
}

variable "dependencies_layer_arn" {
  description = "Optional Lambda layer ARN providing anthropic+pydantic. Empty until built in Stage B."
  type        = string
  default     = ""
}
