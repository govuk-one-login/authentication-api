module "authenticate" {
  source = "../modules/endpoint-module"

  endpoint_name   = "authenticate"
  path_part       = "authenticate"
  endpoint_method = "POST"
  handler_environment_variables = {
    ENVIRONMENT     = var.environment
    BASE_URL        = local.api_base_url
    DYNAMO_ENDPOINT = var.use_localstack ? var.lambda_dynamo_endpoint : null
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.AuthenticateHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id          = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn             = aws_api_gateway_rest_api.di_account_management_api.execution_arn
  api_deployment_stage_name = var.environment
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.account_management_vpc.default_security_group_id
  subnet_id                 = aws_subnet.account_management_subnets.*.id
  environment               = var.environment
  lambda_role_arn           = aws_iam_role.lambda_iam_role.arn
  logging_endpoint_enabled  = var.logging_endpoint_enabled
  logging_endpoint_arn      = var.logging_endpoint_arn
  default_tags              = local.default_tags

  use_localstack = var.use_localstack
}