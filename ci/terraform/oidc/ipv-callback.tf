module "ipv_callback_role_2" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "ipv-callback-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_user_write_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.spot_queue_encryption_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn,
    local.user_profile_encryption_policy_arn,
    aws_iam_policy.spot_queue_write_access_policy.arn
  ]
  extra_tags = {
    Service = "ipv-callback"
  }
}

module "ipv-callback" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "ipv-callback"
  path_part       = var.orch_ipv_callback_enabled ? "ipv-callback-auth" : "ipv-callback"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                                 = var.environment
    IDENTITY_ENABLED                            = var.ipv_api_enabled
    INTERNAl_SECTOR_URI                         = var.internal_sector_uri
    ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED = var.account_intervention_service_action_enabled
    ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED   = var.account_intervention_service_call_enabled
    ACCOUNT_INTERVENTION_SERVICE_URI            = var.account_intervention_service_uri
    ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR = var.account_intervention_service_abort_on_error
    ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT   = var.account_intervention_service_call_timeout
    IPV_AUDIENCE                                = var.ipv_audience
    IPV_AUTHORISATION_CALLBACK_URI              = var.ipv_authorisation_callback_uri
    IPV_AUTHORISATION_CLIENT_ID                 = var.ipv_authorisation_client_id
    IPV_AUTHORISATION_URI                       = var.ipv_authorisation_uri
    IPV_BACKEND_URI                             = var.ipv_backend_uri
    OIDC_API_BASE_URL                           = local.api_base_url
    REDIS_KEY                                   = local.redis_key
    SPOT_QUEUE_URL                              = aws_sqs_queue.spot_request_queue.id
    TXMA_AUDIT_QUEUE_URL                        = module.oidc_txma_audit.queue_url
    AUTH_FRONTEND_BASE_URL                      = "https://${local.frontend_fqdn}/"
    ORCH_FRONTEND_ENABLED                       = var.orch_frontend_enabled
  }
  handler_function_name = "uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler::handleRequest"

  create_endpoint  = true
  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "ipv-callback", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.ipv_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.ipv_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_egress_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.ipv_callback_role_2.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  snapstart = false # uses redis

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
