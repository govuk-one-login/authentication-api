data "terraform_remote_state" "dns" {
  backend = "s3"
  config = {
    bucket      = var.dns_state_bucket
    key         = var.dns_state_key
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  frontend_fqdn               = lookup(data.terraform_remote_state.dns.outputs, "${var.environment}_frontend_url", "")
  oidc_api_fqdn               = lookup(data.terraform_remote_state.dns.outputs, "${var.environment}_api_url", "")
  frontend_api_fqdn           = lookup(data.terraform_remote_state.dns.outputs, "${var.environment}_api_frontend_url", "")
  service_domain_name         = lookup(data.terraform_remote_state.dns.outputs, "${var.environment}_service_domain", "")
  account_management_fqdn     = lookup(data.terraform_remote_state.dns.outputs, "${var.environment}_account_management_url", "")
  account_management_api_fqdn = lookup(data.terraform_remote_state.dns.outputs, "${var.environment}_account_management_api_url", "")
}
