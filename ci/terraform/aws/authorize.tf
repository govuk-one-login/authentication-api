module "authorize" {
  source = "../modules/endpoint-module"

  endpoint-name   = "authorize"
  endpoint-method = "GET"
  handler-environment-variables = {
    BASE_URL = var.api_base_url
  }
  handler-function-name = "uk.gov.di.lambdas.AuthorisationHandler::handleRequest"

  rest_api_id               = module.api-gateway-root.di_authentication_api_id
  root_resource_id          = module.api-gateway-root.root_resource_id
  execution_arn             = module.api-gateway-root.execution_arn
  api-deployment-stage-name = var.api_base_url
  lambda-zip-file           = var.lambda-zip-file
}