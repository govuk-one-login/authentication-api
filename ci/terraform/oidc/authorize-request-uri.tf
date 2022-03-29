module "oidc_authorize_request_uri_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-authorize-request-uri-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
  ]
}

resource "aws_lambda_function" "authorize_request_uri_lambda" {
  function_name = "${var.environment}-authorize-request-uri-lambda"
  role          = module.oidc_authorize_request_uri_role.arn
  handler       = "uk.gov.di.authentication.oidc.lambda.AuthorizeRequestUriHandler::handleRequest"
  timeout       = 60
  memory_size   = 1024

  tracing_config {
    mode = "Active"
  }

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.oidc_api_release_zip.key
  s3_object_version = aws_s3_bucket_object.oidc_api_release_zip.version_id


  environment {
    variables = merge({
      ENVIRONMENT       = var.environment
      OIDC_API_BASE_URL = local.api_base_url
    })
  }
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  runtime = var.handler_runtime

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "authorize_request_uri_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.authorize_request_uri_lambda.function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.authorize_request_uri_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "authorize_request_uri_lambda_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${aws_lambda_function.authorize_request_uri_lambda.function_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.authorize_request_uri_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "authorize_request_uri_lambda_active" {
  name             = "${aws_lambda_function.authorize_request_uri_lambda.function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorize_request_uri_lambda.arn
  function_version = aws_lambda_function.authorize_request_uri_lambda.version
}