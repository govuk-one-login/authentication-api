module "userinfo" {
  source = "../modules/endpoint-module"

  endpoint_name   = "userinfo"
  path_part       = "userinfo"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    BASE_URL             = local.api_base_url
    EVENTS_SNS_TOPIC_ARN = aws_sns_topic.events.arn
    LOCALSTACK_ENDPOINT  = var.use_localstack ? var.localstack_endpoint : null
    REDIS_HOST           = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.sessions_store[0].primary_endpoint_address
    REDIS_PORT           = var.use_localstack ? var.external_redis_port : aws_elasticache_replication_group.sessions_store[0].port
    REDIS_PASSWORD       = var.use_localstack ? var.external_redis_password : random_password.redis_password.result
    REDIS_TLS            = var.redis_use_tls
    DYNAMO_ENDPOINT      = var.use_localstack ? var.lambda_dynamo_endpoint : null
    TOKEN_SIGNING_KEY_ALIAS = aws_kms_alias.id_token_signing_key_alias.name
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.UserInfoHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id          = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn             = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.oidc_api_lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
  lambda_role_arn           = aws_iam_role.lambda_iam_role.arn
  logging_endpoint_enabled  = var.logging_endpoint_enabled
  logging_endpoint_arn      = var.logging_endpoint_arn
  default_tags              = local.default_tags

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_lambda_zip_file       = var.lambda_warmer_zip_file

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
    aws_vpc.authentication,
    aws_subnet.authentication,
    aws_elasticache_replication_group.sessions_store,
  ]
}