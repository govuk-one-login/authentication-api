module "frontend_api_account_interventions_role" {
  count = local.deploy_account_interventions_count

  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-account-interventions-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_user_write_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    ], var.environment == "production" ? [aws_iam_policy.redis_parameter_policy.arn] : [], [
    module.oidc_txma_audit.access_policy_arn,
    ], local.deploy_ticf_cri_count == 1 ? [
    aws_iam_policy.ticf_cri_lambda_invocation_policy[0].arn,
    aws_iam_policy.dynamo_auth_session_read_policy.arn
    ] : [
  aws_iam_policy.dynamo_auth_session_read_policy.arn])
  extra_tags = {
    Service = "account-interventions"
  }
}

module "account_interventions" {
  count = local.deploy_account_interventions_count

  source = "../modules/endpoint-module-v2"

  endpoint_name   = "account-interventions"
  path_part       = "account-interventions"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                                 = var.environment
    TXMA_AUDIT_QUEUE_URL                        = module.oidc_txma_audit.queue_url
    INTERNAl_SECTOR_URI                         = var.internal_sector_uri
    ACCOUNT_INTERVENTION_SERVICE_URI            = var.account_intervention_service_uri
    ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR = var.account_intervention_service_abort_on_error
    ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT   = var.account_intervention_service_call_timeout
    ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED = var.account_intervention_service_action_enabled
    ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED   = var.account_intervention_service_call_enabled
    TICF_CRI_LAMBDA_IDENTIFIER                  = local.deploy_ticf_cri_count == 1 ? module.ticf_cri_lambda[0].endpoint_lambda_alias.arn : null
    INVOKE_TICF_CRI_LAMBDA                      = var.call_ticf_cri
  }

  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.AccountInterventionsHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn


  security_group_ids = [
    local.authentication_security_group_id,
  ]

  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.frontend_api_account_interventions_role[count.index].arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = true

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  snapstart = var.snapstart_enabled
}
