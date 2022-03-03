module "delivery_receipts_api_notify_callback_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "delivery-receipts-api-notify-callback-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.parameter_policy.arn,
    aws_iam_policy.cloudwatch_metrics_delivery-receipts_putdata_policy.arn,
  ]
}

module "notify_callback" {
  source = "../modules/endpoint-module"

  endpoint_name   = "notify-callback"
  path_part       = "notify-callback"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT         = var.environment
    LOCALSTACK_ENDPOINT = var.use_localstack ? var.localstack_endpoint : null
  }
  handler_function_name = "uk.gov.di.authentication.deliveryreceiptsapi.lambda.NotifyCallbackHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.execution_arn

  source_bucket                  = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file                = aws_s3_bucket_object.delivery_receipts_api_release_zip.key
  lambda_zip_file_version        = aws_s3_bucket_object.delivery_receipts_api_release_zip.version_id
  warmer_lambda_zip_file         = null
  warmer_lambda_zip_file_version = null
  code_signing_config_arn        = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.vpc_arn
  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
  ]
  subnet_id                              = local.private_subnet_ids
  lambda_role_arn                        = module.delivery_receipts_api_notify_callback_role.arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = false

  keep_lambda_warm             = false
  warmer_handler_function_name = null
  warmer_security_group_ids    = [local.allow_aws_service_access_security_group_id]
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_delivery_receipts_api,
  ]
}

resource "aws_iam_policy" "cloudwatch_metrics_delivery-receipts_putdata_policy" {
  name_prefix = "cloudwatch-put-delivery-receipts-metrics-policy-"
  path        = "/${var.environment}/delivery-receipts/"
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