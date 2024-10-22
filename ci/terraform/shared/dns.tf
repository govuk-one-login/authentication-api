locals {
  prod           = var.environment == "production" ? "account.gov.uk" : ""
  sandpitdevs    = var.environment == "authdev1" || var.environment == "authdev2" ? "${var.environment}.sandpit.account.gov.uk" : ""
  otherenv       = var.environment != "production" && var.environment != "authdev1" && var.environment != "authdev2" ? "${var.environment}.account.gov.uk" : ""
  service_domain = coalesce(local.prod, local.sandpitdevs, local.otherenv)
}
