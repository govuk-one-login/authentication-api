output "di_authentication_api_id" {
  value = aws_api_gateway_rest_api.di_authentication_api.id
}

output "root_resource_id" {
  value     = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  sensitive = true
}

output "wellknown_resource_id" {
  value     = aws_api_gateway_resource.wellknown_resource.id
  sensitive = true
}

output "connect_resource_id" {
  value     = aws_api_gateway_resource.connect_resource.id
  sensitive = true
}

output "execution_arn" {
  value     = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  sensitive = true
}
