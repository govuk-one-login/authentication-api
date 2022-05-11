module "doc_app_callback_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "doc-app-callback-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.doc_app_auth_kms_policy.arn,
    aws_iam_policy.doc_app_public_signing_key_parameter_policy.arn,
    aws_iam_policy.dynamo_doc_app_write_access_policy.arn,
    aws_iam_policy.dynamo_doc_app_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
  ]
}

module "doc-app-callback" {
  count  = var.doc_app_api_enabled ? 1 : 0
  source = "../modules/endpoint-module"

  endpoint_name   = "doc-checking-app-callback"
  path_part       = "doc-checking-app-callback"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                        = var.environment
    EVENTS_SNS_TOPIC_ARN               = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS            = local.audit_signing_key_alias_name
    LOCALSTACK_ENDPOINT                = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                          = local.redis_key
    DYNAMO_ENDPOINT                    = var.use_localstack ? var.lambda_dynamo_endpoint : null
    DOC_APP_AUTHORISATION_CALLBACK_URI = var.doc_app_authorisation_callback_uri
    DOC_APP_AUTHORISATION_CLIENT_ID    = var.doc_app_authorisation_client_id
    DOC_APP_TOKEN_SIGNING_KEY_ALIAS    = local.doc_app_auth_key_alias_name
    DOC_APP_BACKEND_URI                = var.doc_app_backend_uri
    DOC_APP_CRI_DATA_ENDPOINT          = var.doc_app_cri_data_endpoint
  }
  handler_function_name = "uk.gov.di.authentication.app.lambda.DocAppCallbackHandler::handleRequest"

  create_endpoint  = true
  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = var.endpoint_memory_size

  source_bucket                  = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file                = aws_s3_bucket_object.doc_checking_app_api_release_zip.key
  lambda_zip_file_version        = aws_s3_bucket_object.doc_checking_app_api_release_zip.version_id
  warmer_lambda_zip_file         = aws_s3_bucket_object.warmer_release_zip.key
  warmer_lambda_zip_file_version = aws_s3_bucket_object.warmer_release_zip.version_id
  code_signing_config_arn        = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_oidc_redis_security_group_id,
    local.authentication_egress_security_group_id,
  ]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.doc_app_callback_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = false

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_security_group_ids    = [local.authentication_security_group_id]
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
  ]
}
