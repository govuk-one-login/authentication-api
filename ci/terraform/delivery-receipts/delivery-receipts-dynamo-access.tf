
data "aws_dynamodb_table" "bulk_email_users_table" {
  count = local.deploy_bulk_email_users_count
  name  = "${var.environment}-bulk-email-users"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_iam_policy_document" "bulk_user_email_receipts_dynamo_write_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:UpdateItem",
      "dynamodb:GetItem",
    ]

    resources = [
      data.aws_dynamodb_table.bulk_email_users_table.arn,
      "${data.aws_dynamodb_table.bulk_email_users_table.arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "bulk_user_email_receipts_dynamo_write_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing write access for the Bulk User Email Send lambda to the Dynamo Bulk Email Users table"

  policy = data.aws_iam_policy_document.bulk_user_email_receipts_dynamo_write_access.json
}

data "aws_iam_policy_document" "bulk_user_email_receipts_user_profile_dynamo_read_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]

    resources = [
      data.aws_dynamodb_table.user_profile_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "bulk_user_email_receipts_user_profile_dynamo_read_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing read access for the Bulk User Email Send lambda to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.bulk_user_email_receipts_user_profile_dynamo_read_access.json
}

data "aws_iam_policy_document" "bulk_user_email_dynamo_encryption_key_policy_document" {
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
  name        = "${var.environment}-bulk-user-email-table-receipts-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the bulk user email table"

  policy = data.aws_iam_policy_document.bulk_user_email_dynamo_encryption_key_policy_document.json
}