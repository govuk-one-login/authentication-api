module "lambda_dependencies_layer" {
  source        = "../modules/lambda-layer"
  environment   = var.environment
  layer_name    = "auth-external-api-dependencies"
  zip_file_path = var.auth_ext_lambda_dependencies_zip_file
}

output "dependencies_layer_version" {
  value = module.lambda_dependencies_layer.layer_version
}

locals {
  lambda_layers = [
    module.lambda_dependencies_layer.arn
  ]
}
