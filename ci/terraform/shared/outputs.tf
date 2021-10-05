
output "redis_host" {
  value = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.sessions_store[0].primary_endpoint_address
}

output "redis_port" {
  value = var.use_localstack ? var.external_redis_port : aws_elasticache_replication_group.sessions_store[0].port
}

output "redis_password" {
  sensitive = true
  value     = random_password.redis_password.result
}

output "authentication_security_group_id" {
  value = aws_vpc.authentication.default_security_group_id
}

output "authentication_subnet_ids" {
  value = aws_subnet.authentication.*.id
}

output "lambda_iam_role_arn" {
  value = aws_iam_role.lambda_iam_role.arn
}

output "lambda_iam_role_name" {
  value = aws_iam_role.lambda_iam_role.name
}

output "dynamo_sqs_lambda_iam_role_arn" {
  value = aws_iam_role.dynamo_sqs_lambda_iam_role.arn
}

output "dynamo_sqs_lambda_iam_role_name" {
  value = aws_iam_role.dynamo_sqs_lambda_iam_role.name
}

output "sqs_lambda_iam_role_arn" {
  value = aws_iam_role.sqs_lambda_iam_role.arn
}

output "sqs_lambda_iam_role_name" {
  value = aws_iam_role.sqs_lambda_iam_role.name
}

output "email_lambda_iam_role_arn" {
  value = aws_iam_role.email_lambda_iam_role.arn
}

output "token_lambda_iam_role_arn" {
  value = aws_iam_role.token_lambda_iam_role.arn
}

output "id_token_signing_key_alias_name" {
  value = aws_kms_alias.id_token_signing_key_alias.name
}

output "audit_signing_key_alias_name" {
  value = aws_kms_alias.audit_payload_signing_key_alias.name
}

output "stub_rp_client_credentials" {
  value = [for i, rp in var.stub_rp_clients : {
    client_name = rp.client_name
    client_id   = random_string.stub_rp_client_id[i].result
    private_key = tls_private_key.stub_rp_client_private_key[i].private_key_pem
    public_key  = tls_private_key.stub_rp_client_private_key[i].public_key_pem
  }]
  sensitive = true
}