output "redis_host" {
  value = aws_elasticache_replication_group.sessions_store.primary_endpoint_address
}

output "redis_port" {
  value = aws_elasticache_replication_group.sessions_store.port
}

output "redis_password" {
  sensitive = true
  value     = random_password.redis_password.result
}

output "authentication_vpc_arn" {
  value = local.vpc_arn
}

output "authentication_security_group_id" {
  value = local.allow_aws_service_access_security_group_id
}

output "authentication_egress_security_group_id" {
  value = local.allow_egress_security_group_id
}

output "authentication_oidc_redis_security_group_id" {
  value = aws_security_group.allow_access_to_oidc_redis.id
}

output "authentication_subnet_ids" {
  value = local.private_subnet_ids
}

output "authentication_private_subnet_ids" {
  value = local.private_subnet_ids
}

output "authentication_protected_subnet_ids" {
  value = local.protected_subnet_ids
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

output "pending_email_check_queue_id" {
  value = aws_sqs_queue.pending_email_check_queue.id
}

output "pending_email_check_queue_encryption_key_arn" {
  description = "the ARN of the KMS key used to encrypt payloads in the pending email check queue"
  value       = aws_kms_key.pending_email_check_queue_encryption_key.arn
}

output "pending_email_check_queue_access_policy_arn" {
  description = "the ARN of the IAM policy that allows write access to the pending email check queue"
  value       = aws_iam_policy.pending_email_check_queue_access_policy.arn
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

output "doc_app_auth_signing_key_alias_name" {
  value = aws_kms_alias.doc_app_auth_signing_key_alias.name
}

output "doc_app_auth_signing_key_arn" {
  value = aws_kms_key.doc_app_auth_signing_key.arn
}

output "orch_to_auth_signing_key_alias_name" {
  value = aws_kms_alias.orchestration_to_auth_signing_key_alias.name
}

output "orch_to_auth_signing_key_arn" {
  value = aws_kms_key.orchestration_to_auth_signing_key.arn
}

output "bulk_user_email_table_encryption_key_arn" {
  value = aws_kms_key.bulk_email_users_encryption_key.arn
}

output "auth_id_token_signing_key_alias_name" {
  value = aws_kms_alias.auth_id_token_signing_key_alias.name
}

output "auth_id_token_signing_key_arn" {
  value = aws_kms_key.auth_id_token_signing_key.arn
}

output "access_token_store_signing_key_arn" {
  value = aws_kms_key.access_token_store_signing_key.arn
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

output "stub_relying_party_client_credentials" {
  value = [
    for i, rp in var.stub_rp_clients : {
      client_name = rp.client_name
      client_id   = random_string.stub_relying_party_client_id[rp.client_name].result
      private_key = tls_private_key.stub_relying_party_client_private_key[rp.client_name].private_key_pem_pkcs8
      public_key  = tls_private_key.stub_relying_party_client_private_key[rp.client_name].public_key_pem
    }
  ]
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

output "lambda_code_signing_configuration_arn" {
  value = aws_lambda_code_signing_config.code_signing_config.arn
}

output "auth_code_store_signing_configuration_arn" {
  value = aws_kms_key.auth_code_store_signing_key.arn
}

output "account_modifiers_encryption_policy_arn" {
  value = aws_iam_policy.account_modifiers_encryption_key_kms_policy.arn
}

output "common_passwords_encryption_policy_arn" {
  value = aws_iam_policy.common_passwords_encryption_key_kms_policy.arn
}

output "client_registry_encryption_policy_arn" {
  value = aws_iam_policy.client_registry_encryption_key_kms_policy.arn
}

output "user_credentials_encryption_policy_arn" {
  value = aws_iam_policy.user_credentials_encryption_key_kms_policy.arn
}

output "user_profile_encryption_policy_arn" {
  value = aws_iam_policy.user_profile_encryption_key_kms_policy.arn
}

output "email_check_results_encryption_policy_arn" {
  value = aws_iam_policy.email_check_results_encryption_key_kms_policy.arn
}

output "client_registry_encryption_key_arn" {
  value = aws_kms_key.client_registry_table_encryption_key.arn
}

output "user_profile_kms_key_arn" {
  value = aws_kms_key.user_profile_table_encryption_key.arn
}

output "user_credentials_kms_key_arn" {
  value = aws_kms_key.user_credentials_table_encryption_key.arn
}

output "authentication_attempt_kms_key_arn" {
  value = aws_kms_key.authentication_attempt_encryption_key.arn
}

output "auth_session_table_encryption_key_arn" {
  value = aws_kms_key.auth_session_table_encryption_key.arn
}

output "id_reverification_state_key_arn" {
  value = aws_kms_key.id_reverification_state_table_encryption_key.arn
}
