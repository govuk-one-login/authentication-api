module "api-gateway-root" {
  source = "../modules/api-gateway-root"
  providers = {
    aws = aws.localstack
  }
  environment = var.environment
}

module "userinfo" {
  source        = "../modules/userinfo"
  providers = {
    aws = aws.localstack
  }
  rest_api_id = module.api-gateway-root.di-authentication-api-id
  root_resource_id = module.api-gateway-root.root_resource_id
  execution_arn = module.api-gateway-root.execution_arn
  api-deployment-stage-name = var.api-deployment-stage-name
  lambda-zip-file = var.lambda-zip-file
}

module "token" {
  source = "../modules/token"
  providers = {
    aws = aws.localstack
  }
  rest_api_id = module.api-gateway-root.di-authentication-api-id
  root_resource_id = module.api-gateway-root.root_resource_id
  execution_arn = module.api-gateway-root.execution_arn
  api-deployment-stage-name = var.api-deployment-stage-name
  lambda-zip-file = var.lambda-zip-file
}

module "authorize" {
  source = "../modules/authorise"
  providers = {
    aws = aws.localstack
  }
  rest_api_id = module.api-gateway-root.di-authentication-api-id
  root_resource_id = module.api-gateway-root.root_resource_id
  execution_arn = module.api-gateway-root.execution_arn
  api-deployment-stage-name = var.api-deployment-stage-name
  lambda-zip-file = var.lambda-zip-file
}
