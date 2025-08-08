resource "aws_kms_key" "test_client_secret_key" {
  count                   = var.provision_test_client_secret ? 1 : 0
  description             = "KMS key for encrypting the test client secret"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.key_policy.json

  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
}

resource "aws_kms_alias" "test_client_secret_key_alias" {
  count         = var.provision_test_client_secret ? 1 : 0
  name          = "alias/${var.environment}-test-client-secret-encryption-key"
  target_key_id = aws_kms_key.test_client_secret_key[0].id
}

resource "aws_secretsmanager_secret" "test_client_email_allow_list" {
  count      = var.provision_test_client_secret ? 1 : 0
  name       = "/${var.environment}/test-client-email-allow-list"
  kms_key_id = aws_kms_alias.test_client_secret_key_alias[0].target_key_id
}
