resource "aws_iam_role" "api_gateway_logging_iam_role" {
  name = "${var.environment}-${var.resource_prefix}-gateway-logging-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json

  tags = var.default_tags
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn
}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.api_gateway_rest_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing
    logging_level      = "INFO"
  }
  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.stage.id]
  }
}

data "aws_iam_policy_document" "api_gateway_logging_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-${var.resource_prefix}-api-gateway-logging"
  path        = "/"
  description = "IAM policy for logging for API Gateway"

  policy = data.aws_iam_policy_document.api_gateway_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.api_gateway_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-${var.resource_prefix}-${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn
}
resource "aws_cloudwatch_log_subscription_filter" "waf_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-${var.resource_prefix}-waf-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.waf_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "stage_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.api_gateway_rest_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn
}
resource "aws_cloudwatch_log_subscription_filter" "execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-${var.resource_prefix}-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.stage_execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "access_logs" {
  name              = "${var.environment}-${var.resource_prefix}-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn
}
resource "aws_cloudwatch_log_subscription_filter" "access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-${var.resource_prefix}-access-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
