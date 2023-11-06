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

resource "aws_iam_policy" "doc_app_credential_encryption_key_kms_policy" {
  name        = "${var.environment}-doc-app-credential-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the doc app credential table"

  policy = data.aws_iam_policy_document.doc_app_credential_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "doc_app_credential_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToDocAppCredentialTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.doc_app_credential_table_encryption_key.arn
    ]
  }
}
