
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

output "authentication_vpc_arn" {
  value = aws_vpc.authentication.arn
}

output "authentication_security_group_id" {
  value = aws_security_group.allow_vpc_resources_only.id
}

output "authentication_egress_security_group_id" {
  value = aws_security_group.allow_egress.id
}

output "authentication_oidc_redis_security_group_id" {
  value = aws_security_group.allow_access_to_oidc_redis.id
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

output "id_token_signing_key_arn" {
  value = aws_kms_key.id_token_signing_key.arn
}

output "audit_signing_key_alias_name" {
  value = aws_kms_alias.audit_payload_signing_key_alias.name
}

output "audit_signing_key_arn" {
  value = aws_kms_key.audit_payload_signing_key.arn
}

output "events_topic_encryption_key_arn" {
  value = aws_kms_key.events_topic_encryption.arn
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

output "cloudwatch_encryption_key_arn" {
  value = aws_kms_key.cloudwatch_log_encryption.arn
}

output "sms_bucket_name_arn" {
  value = aws_s3_bucket.smoketest_sms_bucket.arn
}

output "sms_bucket_name" {
  value = aws_s3_bucket.smoketest_sms_bucket.bucket
}

output "lambda_env_vars_encryption_kms_key_arn" {
  value = aws_kms_key.lambda_env_vars_encryption_key.arn
}

output "lambda_parameter_encryption_key_id" {
  value = aws_kms_key.parameter_store_key.id
}

output "lambda_parameter_encryption_alias_id" {
  value = aws_kms_alias.parameter_store_key_alias.id
}

output "redis_ssm_parameter_policy" {
  value = aws_iam_policy.parameter_policy.arn
}

output "pepper_ssm_parameter_policy" {
  value = aws_iam_policy.pepper_parameter_policy.arn
}

output "ipv_capacity_ssm_parameter_policy" {
  value = aws_iam_policy.ipv_capacity_parameter_policy.arn
}