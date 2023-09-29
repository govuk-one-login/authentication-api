output "di_auth_ext_api_id" {
  value = aws_api_gateway_rest_api.di_auth_ext_api.id
}

output "vpce_id" {
  value = data.aws_vpc_endpoint.auth_api_vpc_endpoint.id
}