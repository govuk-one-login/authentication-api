resource "aws_iam_policy" "user_credentials_encryption_key_kms_policy" {
  name        = "${var.environment}-user-credentials-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the user credentials table"

  policy = data.aws_iam_policy_document.user_credentials_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "user_credentials_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToUserCredentialsTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.user_credentials_table_encryption_key.arn
    ]
  }
}