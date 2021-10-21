module "dns" {
  source = "../modules/dns"

  dns_state_bucket = var.dns_state_bucket
  dns_state_key    = var.dns_state_key
  dns_state_role   = var.dns_state_role
  environment      = var.environment

  is_localstack = var.use_localstack
  is_sandpit    = var.environment == "sandpit"
}