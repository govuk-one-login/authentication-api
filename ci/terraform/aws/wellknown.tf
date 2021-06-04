module "wellknown" {
  source = "../modules/wellknown"

  rest_api_id = module.api-gateway-root.di-authentication-api-id
  root_resource_id = module.api-gateway-root.root_resource_id
  execution_arn = module.api-gateway-root.execution_arn
  api-deployment-stage-name = var.api-deployment-stage-name
  lambda-zip-file = var.lambda-zip-file
}