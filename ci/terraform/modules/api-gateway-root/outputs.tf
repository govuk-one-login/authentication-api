output "di_authentication_api_id" {
  value = aws_api_gateway_rest_api.di-authentication-api.id
}

output "root_resource_id" {
  value     = aws_api_gateway_rest_api.di-authentication-api.root_resource_id
  sensitive = true
}

output "wellknown_resource_id" {
  value     = aws_api_gateway_resource.wellknown-resource.id
  sensitive = true
}

output "execution_arn" {
  value     = aws_api_gateway_rest_api.di-authentication-api.execution_arn
  sensitive = true
}
