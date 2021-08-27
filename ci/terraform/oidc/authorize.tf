module "authorize" {
  source = "../modules/endpoint-module"

  endpoint_name   = "authorize"
  path_part       = "authorize"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    BASE_URL             = local.api_base_url
    DOMAIN_NAME          = "${var.environment}.${var.service_domain_name}"
    EVENTS_SNS_TOPIC_ARN = aws_sns_topic.events.arn
    LOGIN_URI            = var.use_localstack ? "http://localhost:3000/" : "https://front.${var.environment}.${var.service_domain_name}/"
    REDIS_HOST           = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.sessions_store[0].primary_endpoint_address
    REDIS_PORT           = var.use_localstack ? var.external_redis_port : aws_elasticache_replication_group.sessions_store[0].port
    REDIS_PASSWORD       = var.use_localstack ? var.external_redis_password : random_password.redis_password.result
    REDIS_TLS            = var.redis_use_tls
    ENVIRONMENT          = var.environment
    DYNAMO_ENDPOINT      = var.use_localstack ? var.lambda_dynamo_endpoint : null
  }
  handler_function_name = "uk.gov.di.lambdas.AuthorisationHandler::handleRequest"

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
