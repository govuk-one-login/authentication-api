resource "aws_lambda_function" "audit_processor_lambda" {
  filename      = var.lambda_zip_file
  function_name = "${var.environment}-audit-processor-example-lambda"
  role          = local.lambda_iam_role_arn
  handler       = "uk.gov.di.authentication.audit.lambda.ExampleAuditHandler::handleRequest"
  timeout       = 30
  memory_size   = 4096
  publish       = true

  tracing_config {
    mode = "Active"
  }

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [local.authentication_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = {
      AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
      LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
      TOKEN_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
    }
  }

  runtime = "java11"

  tags = local.default_tags
}

resource "aws_sns_topic_subscription" "event_stream_subscription" {
  topic_arn = data.aws_sns_topic.event_stream.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.audit_processor_lambda.arn
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.audit_processor_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = local.cloudwatch_key_arn
  retention_in_days = local.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.audit_processor_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${aws_lambda_function.audit_processor_lambda.function_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "active_processor" {
  name             = "${aws_lambda_function.audit_processor_lambda.function_name}-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.audit_processor_lambda.arn
  function_version = aws_lambda_function.audit_processor_lambda.version
}
