module "delivery_receipts_api_notify_callback_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "delivery-receipts-api-notify-callback-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.parameter_policy.arn,
    aws_iam_policy.bulk_user_email_dynamo_encryption_key_kms_policy.arn,
    local.user_profile_encryption_policy_arn,
  ], local.deploy_bulk_email_users_count == 1 ? [aws_iam_policy.bulk_user_email_receipts_dynamo_write_access[0].arn, aws_iam_policy.bulk_user_email_receipts_user_profile_dynamo_read_access.arn] : [])
  extra_tags = {
    Service = "notify-callback"
  }
}

module "notify_callback" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "notify-callback"
  path_part       = "notify-callback"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = merge(var.notify_template_map, {
    ENVIRONMENT             = var.environment
    BULK_USER_EMAIL_ENABLED = local.deploy_bulk_email_users_count
  })
  handler_function_name = "uk.gov.di.authentication.deliveryreceiptsapi.lambda.NotifyCallbackHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.execution_arn
  memory_size      = var.endpoint_memory_size

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.delivery_receipts_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.delivery_receipts_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
  ]
  subnet_id                              = local.private_subnet_ids
  lambda_role_arn                        = module.delivery_receipts_api_notify_callback_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = false

  dynatrace_secret      = local.dynatrace_secret
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  account_alias         = local.aws_account_alias

  snapstart = var.snapstart_enabled

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_delivery_receipts_api,
  ]
}
