locals {
  prod           = var.environment == "production" ? "account.gov.uk" : ""
  newdevs        = var.environment == "authdev3" || var.environment == "authdev1" || var.environment == "authdev2" ? "${var.environment}.dev.account.gov.uk" : ""
  otherenv       = var.environment != "production" && var.environment != "authdev1" && var.environment != "authdev2" && var.environment != "authdev3" ? "${var.environment}.account.gov.uk" : ""
  service_domain = coalesce(local.prod, local.otherenv, local.newdevs)

  frontend_fqdn = "signin.${local.service_domain}"
  oidc_api_fqdn = "oidc.${local.service_domain}"
}
