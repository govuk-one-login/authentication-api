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

resource "aws_iam_policy" "common_passwords_encryption_key_kms_policy" {
  name        = "${var.environment}-common-passwords-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the common passwords table"

  policy = data.aws_iam_policy_document.common_passwords_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "common_passwords_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToCommonPasswordsTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.common_passwords_table_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "client_registry_encryption_key_kms_policy" {
  name        = "${var.environment}-client-registry-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the client registry table"

  policy = data.aws_iam_policy_document.client_registry_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "client_registry_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToClientRegistryTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.client_registry_table_encryption_key.arn
    ]
  }
}
