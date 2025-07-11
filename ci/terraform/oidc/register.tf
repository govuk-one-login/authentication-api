module "client_registry_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "client-registry-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_client_registry_write_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn
  ]
  extra_tags = {
    Service = "register"
  }
}

module "register" {
  count  = var.client_registry_api_enabled ? 1 : 0
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "register"
  path_part       = var.orch_register_enabled ? "register-auth" : "register"
  endpoint_method = ["POST"]

  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    TXMA_AUDIT_QUEUE_URL = module.oidc_txma_audit.queue_url
    OIDC_API_BASE_URL    = local.api_base_url
  }
  handler_function_name = "uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler::handleRequest"

  create_endpoint  = false
  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_resource.register_resource.id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "register", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.client_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.client_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.client_registry_role.arn
  environment                            = var.environment
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = true

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  snapstart = var.snapstart_enabled

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
    aws_api_gateway_resource.register_resource,
  ]
}
