module "reset_password" {
  source = "../modules/endpoint-module"

  endpoint_name   = "reset-password"
  path_part       = "reset-password"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    BASE_URL                 = local.frontend_api_base_url
    DYNAMO_ENDPOINT          = var.use_localstack ? var.lambda_dynamo_endpoint : null
    LOCALSTACK_ENDPOINT      = var.use_localstack ? var.localstack_endpoint : null
    EMAIL_QUEUE_URL          = aws_sqs_queue.email_queue.id
    ENVIRONMENT              = var.environment
    EVENTS_SNS_TOPIC_ARN     = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS  = local.audit_signing_key_alias_name
    REDIS_HOST               = local.external_redis_host
    REDIS_PORT               = local.external_redis_port
    REDIS_PASSWORD           = local.external_redis_password
    REDIS_TLS                = var.redis_use_tls
    SQS_ENDPOINT             = var.use_localstack ? "http://localhost:45678/" : null
    TERMS_CONDITIONS_VERSION = var.terms_and_conditions
  }
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.ResetPasswordHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id          = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn             = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.frontend_api_lambda_zip_file
  security_group_id         = local.authentication_security_group_id
  subnet_id                 = local.authentication_subnet_ids
  lambda_role_arn           = local.dynamo_sqs_lambda_iam_role_arn
  logging_endpoint_enabled  = var.logging_endpoint_enabled
  logging_endpoint_arn      = var.logging_endpoint_arn
  cloudwatch_key_arn        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention  = var.cloudwatch_log_retention
  default_tags              = local.default_tags
  api_key_required          = true

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_lambda_zip_file       = var.lambda_warmer_zip_file

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
