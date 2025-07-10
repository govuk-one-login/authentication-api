locals {
  test_services_api_delete-synthetics_endpoint_name = "synthetics-user"
}
module "test_services_api_delete-synthetics-user_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "test_services-api-delete-synthetics-user-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_test_services_user_read_access_policy.arn,
    aws_iam_policy.dynamo_test_services_user_delete_access_policy.arn,
    module.test_services_txma_audit.access_policy_arn,
  ]
  extra_tags = {
    Service = local.test_services_api_delete-synthetics_endpoint_name
  }
}

module "delete-synthetics-user" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = local.test_services_api_delete-synthetics_endpoint_name
  path_part       = "synthetics-user"
  endpoint_method = ["DELETE"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    SYNTHETICS_USERS     = var.synthetics_users
    TXMA_AUDIT_QUEUE_URL = module.test_services_txma_audit.queue_url
  }
  handler_function_name = "uk.gov.di.authentication.testservices.lambda.DeleteSyntheticsUserHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_test_services_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_test_services_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_test_services_api.execution_arn
  memory_size      = var.endpoint_memory_size

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.test_services_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.test_services_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id = local.authentication_private_subnet_ids

  lambda_role_arn                        = module.test_services_api_delete-synthetics-user_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = true

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  snapstart = var.snapstart_enabled

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_test_services_api,
  ]
}
