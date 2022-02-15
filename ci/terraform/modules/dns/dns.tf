data "terraform_remote_state" "dns" {
  count   = var.is_localstack || var.is_sandpit ? 0 : 1
  backend = "s3"
  config = {
    bucket   = var.dns_state_bucket
    key      = var.dns_state_key
    role_arn = var.dns_state_role
    region   = var.aws_region
  }
}

locals {
  frontend_fqdn               = var.is_localstack ? "localhost:3000" : var.is_sandpit ? "signin.sandpit.auth.ida.digital.cabinet-office.gov.uk" : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_frontend_url", "")
  oidc_api_fqdn               = var.is_localstack ? "localhost:8080" : var.is_sandpit ? "api.sandpit.auth.ida.digital.cabinet-office.gov.uk" : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_api_url", "")
  frontend_api_fqdn           = var.is_localstack ? "localhost:8080" : var.is_sandpit ? "auth.sandpit.auth.ida.digital.cabinet-office.gov.uk" : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_api_frontend_url", "")
  service_domain_name         = var.is_localstack ? "localhost" : var.is_sandpit ? "sandpit.auth.ida.digital.cabinet-office.gov.uk" : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_service_domain", "")
  account_management_fqdn     = var.is_localstack ? "localhost:3000" : var.is_sandpit ? "sandpit.auth.ida.digital.cabinet-office.gov.uk" : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_account_management_url", "")
  account_management_api_fqdn = var.is_localstack ? "localhost:8080" : var.is_sandpit ? "acct-mgmt-api.sandpit.auth.ida.digital.cabinet-office.gov.uk" : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_account_management_api_url", "")
}