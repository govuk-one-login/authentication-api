module "account_management_api_provenance_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-api-provenance-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    module.account_management_txma_audit.access_policy_arn
  ]
}

module "provenance" {
  source = "../modules/endpoint-module"

  endpoint_name   = "account-management-api-provenance"
  path_part       = "provenance"
  endpoint_method = ["GET"]

  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    TXMA_AUDIT_QUEUE_URL = module.account_management_txma_audit.queue_url
  }
  handler_function_name = "uk.gov.di.authentication.shared.lambda.ProvenanceHandler::handleRequest"
  handler_runtime       = "java17"

  provenance_environment_variables = var.provenance_environment_variables

  rest_api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_account_management_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "provenance", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "provenance", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "provenance", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "provenance", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.account_management_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.account_management_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.vpc_arn
  security_group_ids = [
    local.allow_aws_service_access_security_group_id,
  ]

  subnet_id                              = local.private_subnet_ids
  environment                            = var.environment
  lambda_role_arn                        = module.account_management_api_update_password_role.arn
  use_localstack                         = var.use_localstack
  default_tags                           = local.default_tags
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
}
