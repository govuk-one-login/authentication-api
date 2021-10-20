output "frontend_fqdn" {
  value = local.frontend_fqdn
}

output "frontend_url" {
  value = var.is_localstack ? "http://${local.frontend_fqdn}/" : "https://${local.frontend_fqdn}/"
}

output "oidc_api_fqdn" {
  value = local.oidc_api_fqdn
}

output "oidc_api_url" {
  value = var.is_localstack ? "http://${local.oidc_api_fqdn}/" : "https://${local.oidc_api_fqdn}/"
}

output "frontend_api_fqdn" {
  value = local.frontend_api_fqdn
}

output "frontend_api_url" {
  value = var.is_localstack ? "http://${local.frontend_api_fqdn}/" : "https://${local.frontend_api_fqdn}/"
}

output "service_domain_name" {
  value = local.service_domain_name
}

output "account_management_fqdn" {
  value = local.account_management_fqdn
}

output "account_management_url" {
  value = var.is_localstack ? "http://${local.account_management_fqdn}/" : "https://${local.account_management_fqdn}/"
}

output "account_management_api_fqdn" {
  value = local.account_management_api_fqdn
}

output "account_management_api_url" {
  value = var.is_localstack ? "http://${local.account_management_api_fqdn}/" : "https://${local.account_management_api_fqdn}/"
}


