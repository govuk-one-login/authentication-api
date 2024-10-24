module "reverification_result_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "reverification-result_role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.mfa_reset_jar_kms_signing_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
  ]
}

module "reverification_result" {
  source = "../modules/endpoint-module"

  endpoint_name   = "reverification-result"
  path_part       = "reverification-result"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    DYNAMO_ENDPOINT                 = var.use_localstack ? var.lambda_dynamo_endpoint : null
    LOCALSTACK_ENDPOINT             = var.use_localstack ? var.localstack_endpoint : null
    TXMA_AUDIT_QUEUE_URL            = module.oidc_txma_audit.queue_url
    INTERNAl_SECTOR_URI             = var.internal_sector_uri
    REDIS_KEY                       = local.redis_key
    IPV_AUDIENCE                    = var.ipv_audience
    IPV_AUTHORISATION_CALLBACK_URI  = var.ipv_authorisation_callback_uri
    IPV_AUTHORISATION_CLIENT_ID     = var.ipv_authorisation_client_id
    ENVIRONMENT                     = var.environment
    MFA_RESET_JAR_SIGNING_KEY_ALIAS = aws_kms_alias.mfa_reset_jar_signing_key_alias.name
  }

  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.ReverificationResultHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.reverification_result_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = true

  use_localstack = false

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api
  ]
}

module "codedeploy_reverification_result" {
  source               = "../modules/codedeploy"
  endpoint_name        = "reverification-result"
  environment          = var.environment
  lambda_function_name = module.reverification_result.lambda_function_name
  lambda_version       = module.reverification_result.lambda_version
  lambda_alias_name    = module.reverification_result.lambda_alias_name
  lambda_alias_version = module.reverification_result.lambda_alias_version

  skip_canary              = var.skip_canary
  code_deploy_notification = var.code_deploy_notification
}
