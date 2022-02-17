module "frontend_api_verify_code_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-verify-code-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_user_write_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.cloudwatch_metrics_putdata_policy.arn,
  ]
}

module "verify_code" {
  source = "../modules/endpoint-module"

  endpoint_name   = "verify-code"
  path_part       = "verify-code"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                         = var.environment
    BASE_URL                            = local.frontend_api_base_url
    BLOCKED_EMAIL_DURATION              = var.blocked_email_duration
    EVENTS_SNS_TOPIC_ARN                = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS             = local.audit_signing_key_alias_name
    LOCALSTACK_ENDPOINT                 = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                           = local.redis_key
    DYNAMO_ENDPOINT                     = var.use_localstack ? var.lambda_dynamo_endpoint : null
    TERMS_CONDITIONS_VERSION            = var.terms_and_conditions
    TEST_CLIENT_VERIFY_EMAIL_OTP        = var.test_client_verify_email_otp
    TEST_CLIENT_VERIFY_PHONE_NUMBER_OTP = var.test_client_verify_phone_number_otp
    TEST_CLIENTS_ENABLED                = var.test_clients_enabled
  }
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.VerifyCodeHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  source_bucket                  = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file                = aws_s3_bucket_object.frontend_api_release_zip.key
  lambda_zip_file_version        = aws_s3_bucket_object.frontend_api_release_zip.version_id
  warmer_lambda_zip_file         = aws_s3_bucket_object.warmer_release_zip.key
  warmer_lambda_zip_file_version = aws_s3_bucket_object.warmer_release_zip.version_id
  code_signing_config_arn        = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.frontend_api_verify_code_role.arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = true

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_security_group_ids    = [local.authentication_security_group_id]
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
    aws_sqs_queue.email_queue,
  ]
}

resource "aws_iam_policy" "cloudwatch_metrics_putdata_policy" {
  name_prefix = "cloudwatch-put-metrics-policy-"
  path        = "/${var.environment}/frontend-shared/"
  description = "IAM policy enabling pushing metrics to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["cloudwatch:PutMetricData"]
      Resource = ["*"]
    }]
  })
}
