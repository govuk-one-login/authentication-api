output "base_url" {
  value = local.api_base_url
}

output "api_gateway_root_id" {
  value = aws_api_gateway_rest_api.di_authentication_api.id
}

output "token_signing_key_alias" {
  value = local.id_token_signing_key_alias_name
}

output "frontend_api_key" {
  value     = aws_api_gateway_api_key.di_auth_api_key.value
  sensitive = true
}

output "email_queue" {
  value = aws_sqs_queue.email_queue.id
}
