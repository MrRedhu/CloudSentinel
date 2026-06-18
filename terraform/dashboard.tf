locals {
  cs_ns = "CloudSentinel"
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = local.name_prefix

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title  = "Mean time to triage (ms)"
          region = var.region
          view   = "timeSeries"
          period = 300
          metrics = [
            [local.cs_ns, "ProcessingTimeMs", { stat = "Average", label = "avg" }],
            [local.cs_ns, "ProcessingTimeMs", { stat = "p90", label = "p90" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title  = "Estimated Claude cost (USD)"
          region = var.region
          view   = "timeSeries"
          period = 300
          stat   = "Sum"
          metrics = [
            [local.cs_ns, "EstCostUSD"],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6,
        properties = {
          title  = "Tokens per triage"
          region = var.region
          view   = "timeSeries"
          period = 300
          stat   = "Sum"
          metrics = [
            [local.cs_ns, "InputTokens", { label = "input" }],
            [local.cs_ns, "OutputTokens", { label = "output" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6,
        properties = {
          title  = "Triage outcomes"
          region = var.region
          view   = "timeSeries"
          period = 300
          stat   = "Sum"
          metrics = [
            [local.cs_ns, "Failures", { label = "degraded/failed" }],
            ["AWS/Lambda", "Invocations", "FunctionName", local.function_name, { label = "invocations" }],
            ["AWS/Lambda", "Errors", "FunctionName", local.function_name, { label = "lambda errors" }],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 24, height = 6,
        properties = {
          title  = "Lambda duration (ms)"
          region = var.region
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", local.function_name, { stat = "Average", label = "avg" }],
            ["AWS/Lambda", "Duration", "FunctionName", local.function_name, { stat = "Maximum", label = "max" }],
          ]
        }
      },
    ]
  })
}
