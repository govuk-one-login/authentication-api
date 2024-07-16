output "di_auth_ext_api_id" {
  value = module.auth-external-api_gateway.api_gateway_id
}

output "vpce_id" {
  value = data.aws_vpc_endpoint.auth_api_vpc_endpoint.id
}
