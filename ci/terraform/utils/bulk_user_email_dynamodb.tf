
data "aws_dynamodb_table" "bulk_email_users_table" {
  count = local.deploy_bulk_email_users_count
  name  = "${var.environment}-bulk-email-users"
}

data "aws_dynamodb_table" "user_profile_table" {
  count = local.deploy_bulk_email_users_count
  name  = "${var.environment}-user-profile"
}

data "aws_iam_policy_document" "bulk_user_email_dynamo_encryption_key_policy_document" {
  count = local.deploy_bulk_email_users_count
  statement {
    sid    = "AllowAccessToBulkUserEmailTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:GetPublicKey"
    ]
    resources = [
      local.bulk_user_email_table_encryption_key_arn,
    ]
  }
}

resource "aws_iam_policy" "bulk_user_email_dynamo_encryption_key_kms_policy" {
  count       = local.deploy_bulk_email_users_count
  name        = "${var.environment}-bulk-user-email-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the bulk user email table"

  policy = data.aws_iam_policy_document.bulk_user_email_dynamo_encryption_key_policy_document[0].json
}