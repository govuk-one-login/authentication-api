data "terraform_remote_state" "dns" {
  count   = var.frontend_base_url == null && var.frontend_api_url == null && var.oidc_api_url == null && var.service_domain_name == null && var.account_management_url == null ? 1 : 0
  backend = "s3"
  config = {
    bucket   = var.dns_state_bucket
    key      = var.dns_state_key
    role_arn = var.dns_state_role
    region   = var.aws_region
  }
}

locals {
  frontend_base_url      = var.frontend_base_url == null ? lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_frontend_url", "") : var.frontend_base_url
  oidc_api_url           = var.oidc_api_url == null ? lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_api_url", "") : var.oidc_api_url
  frontend_api_url       = var.frontend_api_url == null ? lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_api_frontend_url", "") : var.frontend_api_url
  service_domain_name    = var.service_domain_name == null ? lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_service_domain", "") : var.service_domain_name
  account_management_url = var.account_management_url == null ? lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_account_management_url", "") : var.account_management_url
}