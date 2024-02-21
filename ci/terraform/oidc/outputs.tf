output "base_url" {
  value = local.api_base_url
}

output "frontend_api_base_url" {
  value = local.frontend_api_base_url
}

output "api_gateway_root_id" {
  value = aws_api_gateway_rest_api.di_authentication_api.id
}

output "frontend_api_gateway_root_id" {
  value = aws_api_gateway_rest_api.di_authentication_frontend_api.id
}

output "external_token_signing_key_alias" {
  value = local.id_token_signing_key_alias_name
}

output "ipv_token_auth_key_alias" {
  value = local.ipv_token_auth_key_alias_name
}

output "frontend_api_key" {
  value     = aws_api_gateway_api_key.di_auth_frontend_api_key.value
  sensitive = true
}

output "email_queue" {
  value = aws_sqs_queue.email_queue.id
}

output "analytics_cookie_domain" {
  value = local.service_domain
}

output "events_sns_topic_arn" {
  value = aws_sns_topic.events.arn
}

output "txma_audit_queue_arn" {
  value = module.oidc_txma_audit.queue_arn
}

output "txma_audit_key_arn" {
  value = module.oidc_txma_audit.kms_key_arn
}
