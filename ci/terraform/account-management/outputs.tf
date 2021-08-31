output "base_url" {
  value = local.api_base_url
}

output "api_gateway_root_id" {
  value = aws_api_gateway_rest_api.di_account_management_api.id
}
