output "token_url" {
  value = module.token.base_url
}

output "userinfo_url" {
  value = module.userinfo.base_url
}

output "openid_configuration_discovery_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/.wellknown/openid-configuration"
}