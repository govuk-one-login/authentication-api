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
}

module "delete-synthetics-user" {
  source = "../modules/endpoint-module"

  endpoint_name   = "synthetics-user"
  path_part       = "synthetics-user"
  endpoint_method = ["DELETE"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    LOCALSTACK_ENDPOINT  = var.use_localstack ? var.localstack_endpoint : null
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

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id = local.authentication_private_subnet_ids

  lambda_role_arn                        = module.test_services_api_delete-synthetics-user_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = true

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_test_services_api,
  ]
}

module "codedeploy_synthetics_user" {
  source               = "../modules/codedeploy"
  endpoint_name        = "synthetics-user"
  environment          = var.environment
  lambda_function_name = module.delete-synthetics-user.lambda_function_name
  lambda_version       = module.delete-synthetics-user.lambda_version
  lambda_alias_name    = module.delete-synthetics-user.lambda_alias_name
  lambda_alias_version = module.delete-synthetics-user.lambda_alias_version

  skip_canary              = var.skip_canary
  code_deploy_notification = var.code_deploy_notification
}
