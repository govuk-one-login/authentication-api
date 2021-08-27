module "jwks" {
  source = "../modules/endpoint-module"

  endpoint_name   = "jwks.json"
  path_part       = "jwks.json"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    BASE_URL             = local.api_base_url
    EVENTS_SNS_TOPIC_ARN = aws_sns_topic.events.arn
    LOCALSTACK_ENDPOINT  = var.use_localstack ? var.localstack_endpoint : null
    TOKEN_SIGNING_KEY_ID = aws_kms_key.id_token_signing_key.key_id
  }
  handler_function_name = "uk.gov.di.lambdas.JwksHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id          = aws_api_gateway_resource.wellknown_resource.id
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