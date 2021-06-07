module "api_gateway_root" {
  source = "../modules/api-gateway-root"

  environment = var.environment
}