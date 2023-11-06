module "frontend_api_send_notification_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-send-notification-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn
  ]
}

module "send_notification" {
  source = "../modules/endpoint-module"

  endpoint_name   = "send-notification"
  path_part       = "send-notification"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                            = var.environment
    BLOCKED_EMAIL_DURATION                 = var.blocked_email_duration
    EMAIL_QUEUE_URL                        = aws_sqs_queue.email_queue.id
    TXMA_AUDIT_QUEUE_URL                   = module.oidc_txma_audit.queue_url
    LOCALSTACK_ENDPOINT                    = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                              = local.redis_key
    TEST_CLIENTS_ENABLED                   = var.test_clients_enabled
    DEFAULT_OTP_CODE_EXPIRY                = var.otp_code_ttl_duration
    EMAIL_OTP_ACCOUNT_CREATION_CODE_EXPIRY = var.email_acct_creation_otp_code_ttl_duration
    INTERNAl_SECTOR_URI                    = var.internal_sector_uri
  }
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.SendNotificationHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "send-notification", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "send-notification", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "send-notification", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "send-notification", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.frontend_api_send_notification_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = true

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
    aws_sqs_queue.email_queue,
  ]
}
