resource "aws_iam_policy" "account_modifiers_encryption_key_kms_policy" {
  name        = "${var.environment}-account-modifiers-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the account modifiers table"

  policy = data.aws_iam_policy_document.account_modifiers_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "account_modifiers_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToAccountModifiersTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.account_modifiers_table_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "identity_credentials_encryption_key_kms_policy" {
  name        = "${var.environment}-identity-credentials-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the identity credentials table"

  policy = data.aws_iam_policy_document.identity_credentials_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "identity_credentials_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToIdentityCredentialsTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.identity_credentials_table_encryption_key.arn
    ]
  }
}

