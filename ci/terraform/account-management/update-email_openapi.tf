module "update-email_openapi" {
  source = "../modules/openapi-endpoint-module"

  endpoint_name = "update-email"
  handler_environment_variables = {
    ENVIRONMENT                 = var.environment
    DYNAMO_ENDPOINT             = var.use_localstack ? var.lambda_dynamo_endpoint : null
    EMAIL_QUEUE_URL             = aws_sqs_queue.email_queue.id
    LOCALSTACK_ENDPOINT         = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                   = local.redis_key
    TXMA_AUDIT_QUEUE_URL        = module.account_management_txma_audit.queue_url
    INTERNAl_SECTOR_URI         = var.internal_sector_uri
    SUPPORT_EMAIL_CHECK_ENABLED = var.support_email_check_enabled
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.UpdateEmailHandler::handleRequest"

  memory_size                 = lookup(var.performance_tuning, "update-email", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "update-email", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "update-email", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "update-email", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.account_management_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.account_management_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.vpc_arn
  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
    aws_security_group.allow_access_to_am_redis.id,
  ]
  subnet_id                              = local.private_subnet_ids
  environment                            = var.environment
  lambda_role_arn                        = module.account_management_api_update_email_role.arn
  default_tags                           = local.default_tags
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

}
