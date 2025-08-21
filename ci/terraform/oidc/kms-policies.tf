### ID Token signing key access

data "aws_iam_policy_document" "kms_policy_document" {
  statement {
    sid     = "AllowAccessToKmsSigningKey"
    effect  = "Allow"
    actions = ["kms:GetPublicKey"]
    resources = [
      local.id_token_signing_key_arn,
      aws_kms_key.id_token_signing_key_rsa.arn
    ]
  }
}

resource "aws_iam_policy" "oidc_default_id_token_public_key_kms_policy" {
  name_prefix = "id-token-kms-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing ID token public signing key access"

  policy = data.aws_iam_policy_document.kms_policy_document.json
}

### Audit signing key access

data "aws_iam_policy_document" "audit_payload_kms_signing_policy_document" {
  statement {
    sid       = "AllowAccessToKmsAuditSigningKey"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:Verify"]
    resources = [local.audit_signing_key_arn]
  }
}

resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  name_prefix = "audit-payload-kms-signing-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.audit_payload_kms_signing_policy_document.json
}

### Signing key access for OIDC/Orch API to send signed authorize payload to Authentication

data "aws_iam_policy_document" "orch_to_auth_kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      local.orch_to_auth_signing_key_arn
    ]
  }
}

resource "aws_iam_policy" "orch_to_auth_kms_policy" {
  name_prefix = "kms-orch-to-auth-policy"
  path        = "/${var.environment}/orch-to-auth-kms-signing/"
  description = "IAM policy for managing Orch/OIDC API's authorize endpoint KMS key access"

  policy = data.aws_iam_policy_document.orch_to_auth_kms_policy_document.json
}

### Doc App signing key access

data "aws_iam_policy_document" "doc_app_auth_kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      local.doc_app_auth_signing_key_arn
    ]
  }
}

resource "aws_iam_policy" "doc_app_auth_kms_policy" {
  name_prefix = "kms-doc-app-auth-policy"
  path        = "/${var.environment}/doc-app/"
  description = "IAM policy for managing Doc app authentication KMS key access"

  policy = data.aws_iam_policy_document.doc_app_auth_kms_policy_document.json
}

data "aws_iam_policy_document" "auth_code_dynamo_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToAuthCodeTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:GetPublicKey"
    ]
    resources = [
      local.auth_code_store_signing_configuration_arn
    ]
  }
}

resource "aws_iam_policy" "auth_code_dynamo_encryption_key_kms_policy" {
  name        = "${var.environment}-auth-code-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the auth code table"

  policy = data.aws_iam_policy_document.auth_code_dynamo_encryption_key_policy_document.json
}

### Encrypted VC storage token signing key access

data "aws_iam_policy_document" "storage_token_kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToVcTokenKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.storage_token_signing_key_ecc.arn
    ]
  }
}

resource "aws_iam_policy" "storage_token_kms_signing_policy" {
  name_prefix = "kms-signing-policy"
  path        = "/${var.environment}/storage-token/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of storage token payloads"

  policy = data.aws_iam_policy_document.storage_token_kms_signing_policy_document.json
}

### MFA reset storage token signing key access

data "aws_iam_policy_document" "mfa_reset_storage_token_kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToMfaResetStorageTokenKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.mfa_reset_token_signing_key_ecc.arn
    ]
  }
}

resource "aws_iam_policy" "mfa_reset_storage_token_kms_signing_policy" {
  name_prefix = "kms-mfa-reset-storage-token-signing-policy"
  path        = "/${var.environment}/mfa-reset-storage-token/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of MFA reset storage token payloads"

  policy = data.aws_iam_policy_document.mfa_reset_storage_token_kms_signing_policy_document.json
}

# Policy for mfa-reset-authorize lambda to access the key used to sign the storage token claim in the MFA reset JAR
data "aws_iam_policy_document" "mfa_reset_token_kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey" #Token Service calls GetPublicKey to derive KeyId
    ]
    resources = [
      aws_kms_key.mfa_reset_token_signing_key_ecc.arn
    ]
  }
}

resource "aws_iam_policy" "mfa_reset_token_kms_signing_policy" {
  name_prefix = "kms-mfa-reset-token-signing-policy"
  path        = "/${var.environment}/mfa-reset-storage-token/"
  description = "IAM policy for manging KMS connection for a lambda which allows signing of the storage token claim sent from Auth to IPV when re-authenticating for MFA reset"

  policy = data.aws_iam_policy_document.mfa_reset_token_kms_signing_policy_document.json
}

# Policy for mfa-reset-authorize lambda to access the key used to sign the MFA reset JAR
# NOTE: Cannot use the alias to identify a KMS key: https://docs.aws.amazon.com/kms/latest/developerguide/cmks-in-iam-policies.html
data "aws_iam_policy_document" "ipv_reverification_request_signing_key_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey" #JWT Service calls GetPublicKey to derive KeyId
    ]
    resources = [
      aws_kms_key.ipv_reverification_request_signing_key_v2.arn
    ]
  }
}



resource "aws_iam_policy" "ipv_reverification_request_signing_key_policy" {
  name_prefix = "kms-mfa-reset-jar-signing-policy"
  path        = "/${var.environment}/mfa-reset-jar/"
  description = "IAM policy for manging KMS connection for a lambda which allows signing of the JARs sent from Auth to IPV when re-authenticating for MFA reset"

  policy = data.aws_iam_policy_document.ipv_reverification_request_signing_key_policy_document.json
}


### MFA reset JAR signing key access
# NOTE: Cannot use the alias to identify a KMS key: https://docs.aws.amazon.com/kms/latest/developerguide/cmks-in-iam-policies.html
data "aws_iam_policy_document" "mfa_reset_jar_jwk_document" {
  statement {
    sid    = "AllowAccessToJarSigningKmsPublicKey"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.ipv_reverification_request_signing_key_v2.arn
    ]
  }
}

resource "aws_iam_policy" "mfa_reset_jar_kms_signing_jwk_policy" {
  name_prefix = "kms-mfa-reset-jar-signing-jwk-policy"
  path        = "/${var.environment}/mfa-reset-jar-jwk-policy/"
  description = "IAM policy for a lambda to publish the JWK for the MFA reset JAR signing key"

  policy = data.aws_iam_policy_document.mfa_reset_jar_jwk_document.json
}
