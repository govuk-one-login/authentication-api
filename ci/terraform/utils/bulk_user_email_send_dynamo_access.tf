data "aws_iam_policy_document" "bulk_user_email_send_dynamo_write_access" {
  count = local.deploy_bulk_email_users_count
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]

    resources = [
      data.aws_dynamodb_table.bulk_email_users_table[0].arn,
      "${data.aws_dynamodb_table.bulk_email_users_table[0].arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "bulk_user_email_send_dynamo_write_access" {
  count       = local.deploy_bulk_email_users_count
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing write access for the Bulk User Email Send lambda to the Dynamo Bulk Email Users table"

  policy = data.aws_iam_policy_document.bulk_user_email_send_dynamo_write_access[0].json
}


data "aws_iam_policy_document" "bulk_user_email_send_dynamo_read_access" {
  count = local.deploy_bulk_email_users_count
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]

    resources = [
      data.aws_dynamodb_table.bulk_email_users_table[0].arn,
      data.aws_dynamodb_table.user_profile_table[0].arn,
      "${data.aws_dynamodb_table.bulk_email_users_table[0].arn}/index/*",
      "${data.aws_dynamodb_table.user_profile_table[0].arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowAccessToKms"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    resources = [local.user_profile_kms_key_arn]
  }
}

resource "aws_iam_policy" "bulk_user_email_send_dynamo_read_access" {
  count       = local.deploy_bulk_email_users_count
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing read access for the Bulk User Email Send lambda to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.bulk_user_email_send_dynamo_read_access[0].json
}
