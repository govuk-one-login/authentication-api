resource "aws_kms_key" "storage_token_signing_key_ecc" {
  description              = "KMS signing key (ECC) for VC storage token"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  tags = local.default_tags
}

resource "aws_kms_alias" "storage_token_signing_key_alias" {
  name          = "alias/${var.environment}-storage-token-signing-key-ecc-alias"
  target_key_id = aws_kms_key.storage_token_signing_key_ecc.key_id
}