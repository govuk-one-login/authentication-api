resource "aws_lambda_function" "spot_response_lambda" {
  count         = var.ipv_api_enabled ? 1 : 0
  filename      = var.ipv_api_lambda_zip_file
  function_name = "${var.environment}-spot-response-lambda"
  role          = module.spot_response_role.arn
  handler       = "uk.gov.di.authentication.ipv-api.lambda.SPOTResponseHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  source_code_hash = filebase64sha256(var.ipv_api_lambda_zip_file)
  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = merge({
      ENVIRONMENT       = var.environment
      FRONTEND_BASE_URL = module.dns.frontend_url
      DYNAMO_ENDPOINT   = var.use_localstack ? var.lambda_dynamo_endpoint : null

    })
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "spot_response_lambda_log_group" {
  count = var.use_localstack || !var.ipv_api_enabled ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.spot_response_lambda[0].function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.spot_response_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "spot_response_lambda_log_subscription" {
  count           = var.logging_endpoint_enabled && var.ipv_api_enabled ? 1 : 0
  name            = "${aws_lambda_function.spot_response_lambda[0].function_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.spot_response_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "spot_response_lambda_active" {
  count            = var.ipv_api_enabled ? 1 : 0
  name             = "${aws_lambda_function.spot_response_lambda[0].function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.spot_response_lambda[0].arn
  function_version = aws_lambda_function.spot_response_lambda[0].version
}