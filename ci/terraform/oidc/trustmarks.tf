module "oidc_trustmarks_role" {
  source = "../modules/lambda-role"

  role_name   = "oidc-trustmarks-role"
  environment = var.environment
  vpc_arn     = local.authentication_vpc_arn
  extra_tags = {
    Service = "trustmarks"
  }
}

module "trustmarks" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "trustmark"
  path_part       = var.orch_trustmark_enabled ? "trustmark-auth" : "trustmark"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT              = var.environment
    OIDC_API_BASE_URL        = local.api_base_url
    HEADERS_CASE_INSENSITIVE = "false"
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.TrustMarkHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "trustmark", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_trustmarks_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
