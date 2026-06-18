# Deployment package: zip of src/. Dependencies (anthropic, pydantic) ship via a
# Lambda layer built in Stage B (var.dependencies_layer_arn); boto3 is provided
# by the runtime. handler.py (the entrypoint) is added in Stage B — until then
# this zips whatever is in src/, which is fine because we don't `apply` in Stage A.
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/../build/function.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}

resource "aws_lambda_function" "triage" {
  function_name = local.function_name
  role          = aws_iam_role.lambda.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"

  # An LLM call needs far more than the 3s default; keep out of a VPC so the
  # function has default internet egress to api.anthropic.com.
  timeout     = 60
  memory_size = 512

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  layers = [aws_lambda_layer_version.deps.arn]

  environment {
    variables = {
      CLOUDSENTINEL_SECRET_ID = var.anthropic_secret_name
      SLACK_SECRET_ID         = var.slack_secret_name
      DEDUP_TABLE             = aws_dynamodb_table.dedup.name
      AUDIT_TABLE             = aws_dynamodb_table.audit.name
      REPORTS_BUCKET          = aws_s3_bucket.reports.bucket
      ALERTS_TOPIC_ARN        = aws_sns_topic.alerts.arn
      GUARDDUTY_DETECTOR_ID   = aws_guardduty_detector.main.id
      METRICS_NAMESPACE       = "CloudSentinel"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}
