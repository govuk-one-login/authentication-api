output "token_url" {
  value = "http://localhost:45678/restapis/${module.api-gateway-root.di_authentication_api_id}/${var.environment}/_user_request_/token"
}

output "authorise_url" {
  value = "http://localhost:45678/restapis/${module.api-gateway-root.di_authentication_api_id}/${var.environment}/_user_request_/authorize"
}

output "userinfo_url" {
  value = "http://localhost:45678/restapis/${module.api-gateway-root.di_authentication_api_id}/${var.environment}/_user_request_/userinfo"
}

output "api_gateway_root_id" {
  value = module.api-gateway-root.di_authentication_api_id
}