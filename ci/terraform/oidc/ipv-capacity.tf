module "ipv_capacity_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "ipv-capacity-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.ipv_capacity_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn
  ]
  extra_tags = {
    Service = "ipv-capacity"
  }
}

module "ipv-capacity" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "ipv-capacity"
  path_part       = "ipv-capacity"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                    = var.environment
    TXMA_AUDIT_QUEUE_URL           = module.oidc_txma_audit.queue_url
    REDIS_KEY                      = var.environment == "production" ? local.redis_key : null
    IPV_AUTHORISATION_URI          = var.ipv_authorisation_uri
    IPV_AUTHORISATION_CALLBACK_URI = var.ipv_authorisation_callback_uri
    IPV_AUTHORISATION_CLIENT_ID    = var.ipv_authorisation_client_id
    OIDC_API_BASE_URL              = local.api_base_url
  }
  handler_function_name = "uk.gov.di.authentication.ipv.lambda.IPVCapacityHandler::handleRequest"

  create_endpoint  = true
  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "ipv-capacity", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "ipv-capacity", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "ipv-capacity", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "ipv-capacity", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.ipv_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.ipv_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = concat([
    local.authentication_security_group_id,
  ], var.environment == "production" ? [local.authentication_oidc_redis_security_group_id] : [])

  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.ipv_capacity_role.arn
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
