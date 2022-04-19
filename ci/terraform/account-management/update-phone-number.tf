module "account_management_api_update_phone_number_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-api-update-phone-number-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_am_user_read_access_policy.arn,
    aws_iam_policy.dynamo_am_user_write_access_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.parameter_policy.arn
  ]
}

module "update_phone_number" {
  source = "../modules/endpoint-module"

  endpoint_name   = "update-phone-number"
  path_part       = "update-phone-number"
  endpoint_method = "POST"
  handler_environment_variables = {
    ENVIRONMENT             = var.environment
    DYNAMO_ENDPOINT         = var.use_localstack ? var.lambda_dynamo_endpoint : null
    EMAIL_QUEUE_URL         = aws_sqs_queue.email_queue.id
    LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY               = local.redis_key
    EVENTS_SNS_TOPIC_ARN    = data.aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.UpdatePhoneNumberHandler::handleRequest"

  authorizer_id    = aws_api_gateway_authorizer.di_account_management_api.id
  rest_api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_account_management_api.execution_arn
  memory_size      = var.endpoint_memory_size

  source_bucket                  = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file                = aws_s3_bucket_object.account_management_api_release_zip.key
  lambda_zip_file_version        = aws_s3_bucket_object.account_management_api_release_zip.version_id
  warmer_lambda_zip_file         = aws_s3_bucket_object.warmer_release_zip.key
  warmer_lambda_zip_file_version = aws_s3_bucket_object.warmer_release_zip.version_id
  code_signing_config_arn        = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.vpc_arn
  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
    aws_security_group.allow_access_to_am_redis.id,
  ]
  subnet_id                              = local.private_subnet_ids
  environment                            = var.environment
  lambda_role_arn                        = module.account_management_api_update_phone_number_role.arn
  use_localstack                         = var.use_localstack
  default_tags                           = local.default_tags
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_security_group_ids    = [local.allow_aws_service_access_security_group_id]
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }
}