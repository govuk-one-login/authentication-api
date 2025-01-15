module "oidc_api_lambda_dependencies_layer" {
  source        = "../modules/lambda-layer"
  environment   = var.environment
  layer_name    = "oidc-api-dependencies"
  zip_file_path = var.oidc_api_lambda_dependencies_zip_file
}

module "frontend_api_lambda_dependencies_layer" {
  source        = "../modules/lambda-layer"
  environment   = var.environment
  layer_name    = "frontend-api-dependencies"
  zip_file_path = var.frontend_api_lambda_dependencies_zip_file
}

module "client_registry_api_lambda_dependencies_layer" {
  source        = "../modules/lambda-layer"
  environment   = var.environment
  layer_name    = "client-registry-api-dependencies"
  zip_file_path = var.client_registry_api_lambda_dependencies_zip_file
}

module "ipv_api_lambda_dependencies_layer" {
  source        = "../modules/lambda-layer"
  environment   = var.environment
  layer_name    = "ipv-api-dependencies"
  zip_file_path = var.ipv_api_lambda_dependencies_zip_file
}

module "doc_checking_app_api_lambda_dependencies_layer" {
  source        = "../modules/lambda-layer"
  environment   = var.environment
  layer_name    = "doc-checking-app-api-dependencies"
  zip_file_path = var.doc_checking_app_api_lambda_dependencies_zip_file
}

output "dependencies_layer_versions" {
  value = {
    oidc_api             = module.oidc_api_lambda_dependencies_layer.layer_version
    frontend_api         = module.frontend_api_lambda_dependencies_layer.layer_version
    client_registry_api  = module.client_registry_api_lambda_dependencies_layer.layer_version
    ipv_api              = module.ipv_api_lambda_dependencies_layer.layer_version
    doc_checking_app_api = module.doc_checking_app_api_lambda_dependencies_layer.layer_version
  }
}
