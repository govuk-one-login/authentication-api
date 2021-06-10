output "token_url" {
  value = module.token.base_url
}

output "userinfo_url" {
  value = module.userinfo.base_url
}

output "authorise_url" {
  value = module.authorize.base_url
}

output "jwks_url" {
  value = module.jwks.base_url
}

output "signup_url" {
  value = module.signup.base_url
}

output "register_url" {
  value = module.register.base_url
}

output "userexists_url" {
  value = module.userexists.base_url
}

output "openid_configuration_discovery_url" {
  value = "http://localhost:45678/restapis/${module.api_gateway_root.di_authentication_api_id}/${var.environment}/_user_request_/.wellknown/openid-configuration"
}