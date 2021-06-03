module "token" {
  source = "../modules/token"

  rest_api_id = aws_api_gateway_rest_api.di-authentication-api.id
  root_resource_id = aws_api_gateway_rest_api.di-authentication-api.root_resource_id
  execution_arn = aws_api_gateway_rest_api.di-authentication-api.execution_arn
  api-deployment-stage-name = var.api-deployment-stage-name
  lambda-zip-file = var.lambda-zip-file
}