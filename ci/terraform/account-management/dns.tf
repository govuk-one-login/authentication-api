locals {
  service_domain = var.environment == "production" ? "account.gov.uk" : "${var.environment}.account.gov.uk"

  account_management_fqdn     = local.service_domain
  account_management_api_fqdn = "manage.${local.service_domain}"
  frontend_fqdn               = "signin.${local.service_domain}"
  frontend_api_fqdn           = "auth.${local.service_domain}"
  oidc_api_fqdn               = "oidc.${local.service_domain}"
}
