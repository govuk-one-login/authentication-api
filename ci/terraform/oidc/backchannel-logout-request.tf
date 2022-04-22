module "backchannel_logout_request_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "backchannel-logout-request-role"

  policies_to_attach = [
    aws_iam_policy.oidc_token_kms_signing_policy.arn
  ]
}

resource "aws_lambda_function" "backchannel_logout_request_lambda" {
  function_name = "${var.environment}-backchannel-logout-request-lambda"
  role          = module.backchannel_logout_request_role.arn
  handler       = "uk.gov.di.authentication.oidc.lambda.BackChannelLogoutRequestHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.oidc_api_release_zip.key
  s3_object_version = aws_s3_bucket_object.oidc_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  environment {
    variables = merge({
      ENVIRONMENT             = var.environment
      OIDC_API_BASE_URL       = local.api_base_url
      TOKEN_SIGNING_KEY_ALIAS = local.id_token_signing_key_alias_name
      LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
    })
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "backchannel_logout_request_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.backchannel_logout_request_lambda.function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.backchannel_logout_request_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "backchannel_logout_request_lambda_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.backchannel_logout_request_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.backchannel_logout_request_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_lambda_alias" "backchannel_logout_request_lambda_active" {
  name             = "${aws_lambda_function.backchannel_logout_request_lambda.function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.backchannel_logout_request_lambda.arn
  function_version = aws_lambda_function.backchannel_logout_request_lambda.version
}

resource "aws_lambda_event_source_mapping" "backchannel_logout_lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.back_channel_logout_queue.arn
  function_name    = aws_lambda_function.backchannel_logout_request_lambda.arn

  depends_on = [
    aws_sqs_queue.back_channel_logout_queue,
    aws_sqs_queue_policy.back_channel_logout_queue_policy,
    aws_lambda_function.backchannel_logout_request_lambda
  ]
}