module "send-otp-notification_openapi" {
  source = "../modules/openapi-endpoint-module"

  endpoint_name = "send-otp-notification"
  environment   = var.environment

  handler_environment_variables = {
    ENVIRONMENT                            = var.environment
    EMAIL_QUEUE_URL                        = aws_sqs_queue.email_queue.id
    PENDING_EMAIL_CHECK_QUEUE_URL          = local.pending_email_check_queue_id
    SUPPORT_EMAIL_CHECK_ENABLED            = var.support_email_check_enabled
    DYNAMO_ENDPOINT                        = var.use_localstack ? var.lambda_dynamo_endpoint : null
    LOCALSTACK_ENDPOINT                    = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                              = local.redis_key
    TXMA_AUDIT_QUEUE_URL                   = module.account_management_txma_audit.queue_url
    LOCKOUT_DURATION                       = var.lockout_duration
    DEFAULT_OTP_CODE_EXPIRY                = var.otp_code_ttl_duration
    EMAIL_OTP_ACCOUNT_CREATION_CODE_EXPIRY = var.email_acct_creation_otp_code_ttl_duration
    INTERNAl_SECTOR_URI                    = var.internal_sector_uri
    TEST_CLIENT_VERIFY_EMAIL_OTP           = var.test_client_verify_email_otp
    TEST_CLIENT_VERIFY_PHONE_NUMBER_OTP    = var.test_client_verify_phone_number_otp
    TEST_CLIENTS_ENABLED                   = var.test_clients_enabled
    SUPPORT_EMAIL_CHECK_ENABLED            = var.support_email_check_enabled
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.SendOtpNotificationHandler::handleRequest"

  memory_size                 = lookup(var.performance_tuning, "send-otp-notification", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "send-otp-notification", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "send-otp-notification", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "send-otp-notification", local.default_performance_parameters).scaling_trigger

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
  lambda_role_arn                        = module.account_management_api_send_notification_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  depends_on = [
    aws_elasticache_replication_group.account_management_sessions_store,
  ]
}
