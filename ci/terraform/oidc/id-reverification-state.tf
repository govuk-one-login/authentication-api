module "id_reverification_state_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "id-reverification-state-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    module.oidc_txma_audit.access_policy_arn,
    aws_iam_policy.dynamo_id_reverification_state_read_policy.arn,
  ]
  extra_tags = {
    Service = "id-reverification-state"
  }
}

module "id_reverification_state" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "id-reverification-state"
  path_part       = "id-reverification-state"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT          = var.environment,
    TXMA_AUDIT_QUEUE_URL = module.oidc_txma_audit.queue_url
  }

  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.IDReverificationStateHandler::handleRequest"
  runbook_link          = "https://govukverify.atlassian.net/l/cp/LfLKwP4s"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "id-reverification-state", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "id-reverification-state", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "id-reverification-state", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "id-reverification-state", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.id_reverification_state_role.arn
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
    aws_api_gateway_rest_api.di_authentication_frontend_api
  ]
}
