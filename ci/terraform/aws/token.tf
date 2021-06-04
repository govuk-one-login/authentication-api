module "token" {
  source = "../modules/token"

  rest_api_id = module.api-gateway-root.di_authentication_api_id
  root_resource_id = module.api-gateway-root.root_resource_id
  execution_arn = module.api-gateway-root.execution_arn
  api-deployment-stage-name = var.api_deployment_stage_name
  lambda-zip-file = var.lambda-zip-file
}