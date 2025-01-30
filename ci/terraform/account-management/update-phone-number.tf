module "account_management_api_update_phone_number_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-api-update-phone-number-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_am_user_read_access_policy.arn,
    aws_iam_policy.dynamo_am_user_write_access_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.parameter_policy.arn,
    module.account_management_txma_audit.access_policy_arn,
    local.user_profile_encryption_policy_arn
  ]
  extra_tags = {
    Service = "update-phone-number"
  }
}

module "update_phone_number" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "update-phone-number"
  path_part       = "update-phone-number"
  endpoint_method = ["POST"]
  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    EMAIL_QUEUE_URL      = aws_sqs_queue.email_queue.id
    REDIS_KEY            = local.redis_key
    TXMA_AUDIT_QUEUE_URL = module.account_management_txma_audit.queue_url
    INTERNAl_SECTOR_URI  = var.internal_sector_uri
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.UpdatePhoneNumberHandler::handleRequest"

  authorizer_id    = aws_api_gateway_authorizer.di_account_management_api.id
  rest_api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_account_management_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "update-phone-number", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "update-phone-number", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "update-phone-number", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "update-phone-number", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.account_management_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.account_management_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  lambda_layers = local.lambda_layers

  authentication_vpc_arn = local.vpc_arn

  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
    aws_security_group.allow_access_to_am_redis.id,
  ]
  subnet_id                              = local.private_subnet_ids
  environment                            = var.environment
  lambda_role_arn                        = module.account_management_api_update_phone_number_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [module.account_management_api_update_phone_number_role]
}
