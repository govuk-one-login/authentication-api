module "fraud_realtime_logging_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "fraud-realtime-logging"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.read_from_queue_policy.arn,
    aws_iam_policy.fraud_realtime_logging_audit_payload_kms_verification.arn
  ]
}

resource "aws_iam_policy" "fraud_realtime_logging_audit_payload_kms_verification" {
  name        = "payload-kms-verification"
  path        = "/${var.environment}/fraud-realtime-logging/"
  description = "IAM policy for a lambda needing to verify payload signatures"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:Verify"
      ]

      Resource = [
        local.audit_signing_key_arn,
      ]
    }]
  })
}

resource "aws_lambda_function" "fraud_realtime_logging_lambda" {
  filename      = var.lambda_zip_file
  function_name = "${var.environment}-fraud-realtime-logging-lambda"
  role          = module.fraud_realtime_logging_role.arn
  handler       = "uk.gov.di.authentication.audit.lambda.CounterFraudAuditLambda::handleRequest"
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
    }
  }

  runtime = "java11"

  tags = local.default_tags
}

resource "aws_sns_topic_subscription" "fraud_realtime_logging_lambda_subscription" {
  topic_arn = data.aws_sns_topic.event_stream.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.fraud_realtime_logging_lambda.function_name
}

resource "aws_lambda_permission" "sns_can_execute_subscriber_fraud_realtime_logging_lambda" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fraud_realtime_logging_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = data.aws_sns_topic.event_stream.arn
}

resource "aws_cloudwatch_log_group" "fraud_realtime_logging_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.fraud_realtime_logging_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = local.cloudwatch_key_arn
  retention_in_days = 1 # We shouldn't hold onto this for long

  depends_on = [
    aws_lambda_function.fraud_realtime_logging_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "fraud_realtime_logging_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${aws_lambda_function.fraud_realtime_logging_lambda.function_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "fraud_realtime_logging_lambda_active" {
  name             = "${aws_lambda_function.fraud_realtime_logging_lambda.function_name}-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.fraud_realtime_logging_lambda.arn
  function_version = aws_lambda_function.fraud_realtime_logging_lambda.version
}