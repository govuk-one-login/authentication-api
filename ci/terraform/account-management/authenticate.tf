module "account_management_api_authenticate_role" {
  source      = "../modules/lambda-role-policy-reduction"
  environment = var.environment
  role_name   = "account-management-api-authenticate-role"
  vpc_arn     = local.vpc_arn

  policy_documents_to_attach = {
    additional = [
      data.aws_iam_policy_document.dynamo_user_read_policy_document.json,
      data.aws_iam_policy_document.account_management_audit_payload_kms_signing_policy_document.json,
      data.aws_iam_policy_document.redis_parameter_policy.json,
      module.account_management_txma_audit.access_policy_document.json
    ]
  }
}

module "authenticate" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "authenticate"
  path_part       = "authenticate"
  endpoint_method = ["POST"]
  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    DYNAMO_ENDPOINT      = var.use_localstack ? var.lambda_dynamo_endpoint : null
    INTERNAl_SECTOR_URI  = var.internal_sector_uri
    LOCALSTACK_ENDPOINT  = var.use_localstack ? var.localstack_endpoint : null
    TXMA_AUDIT_QUEUE_URL = module.account_management_txma_audit.queue_url
    REDIS_KEY            = local.redis_key
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.AuthenticateHandler::handleRequest"

  authorizer_id    = aws_api_gateway_authorizer.di_account_management_api.id
  rest_api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_account_management_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "authenticate", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "authenticate", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "authenticate", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "authenticate", local.default_performance_parameters).scaling_trigger

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
  environment                            = var.environment
  lambda_role_arn                        = module.account_management_api_authenticate_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  account_alias         = data.aws_iam_account_alias.current.account_alias
  slack_event_topic_arn = data.aws_sns_topic.slack_events.arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [module.account_management_api_authenticate_role]
}
