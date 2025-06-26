module "account_management_api_mfa_methods_retrieve_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account_management_api_mfa_methods_retrieve_role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_am_user_read_access_policy.arn,
    aws_iam_policy.dynamo_am_user_write_access_policy.arn
  ]
  extra_tags = {
    Service = "mfa-methods-retrieve"
  }
}

module "mfa-methods-retrieve" {
  source = "../modules/endpoint-lambda"

  endpoint_name = "mfa-methods-retrieve"
  handler_environment_variables = {
    ENVIRONMENT                       = var.environment
    REDIS_KEY                         = local.redis_key
    TXMA_AUDIT_QUEUE_URL              = module.account_management_txma_audit.queue_url
    INTERNAl_SECTOR_URI               = var.internal_sector_uri
    MFA_METHOD_MANAGEMENT_API_ENABLED = var.mfa_method_management_api_enabled
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.MFAMethodsRetrieveHandler::handleRequest"

  memory_size                 = lookup(var.performance_tuning, "mfa-methods-retrieve", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "mfa-methods-retrieve", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "mfa-methods-retrieve", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "mfa-methods-retrieve", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.account_management_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.account_management_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
    aws_security_group.allow_access_to_am_redis.id,
  ]
  subnet_id                              = local.private_subnet_ids
  environment                            = var.environment
  lambda_role_arn                        = module.account_management_api_mfa_methods_retrieve_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  runbook_link                          = "https://govukverify.atlassian.net/wiki/x/HIHpRQE"
  lambda_log_alarm_threshold            = 1
  lambda_log_alarm_error_rate_threshold = 25

  depends_on = [module.account_management_api_mfa_methods_retrieve_role]
}
