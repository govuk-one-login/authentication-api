resource "aws_lambda_function" "endpoint_lambda" {
  filename      = var.lambda_zip_file
  function_name = replace("${var.environment}-${var.endpoint_name}-lambda", ".", "")
  role          = var.lambda_role_arn
  handler       = var.handler_function_name
  timeout       = 30
  memory_size   = 4096
  publish       = true

  tracing_config {
    mode = "Active"
  }

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [var.security_group_id]
    subnet_ids         = var.subnet_id
  }
  environment {
    variables = merge(var.handler_environment_variables, {
      WARMER_DELAY = var.warmer_delay_millis
    })
  }

  runtime = var.handler_runtime

  tags = var.default_tags
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.endpoint_lambda.function_name}"
  tags              = var.default_tags
  kms_key_id        = var.cloudwatch_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.endpoint_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.endpoint_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "endpoint_lambda" {
  name             = replace("${var.environment}-${var.endpoint_name}-lambda-active", ".", "")
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.endpoint_lambda.arn
  function_version = aws_lambda_function.endpoint_lambda.version
}
