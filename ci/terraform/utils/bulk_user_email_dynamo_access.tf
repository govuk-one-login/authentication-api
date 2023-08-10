data "aws_dynamodb_table" "bulk_email_users" {
  count = local.deploy_bulk_email_users_count
  name  = "${var.environment}-bulk-email-users"
}

data "aws_iam_policy_document" "bulk_email_users_full_access" {
  count = local.deploy_bulk_email_users_count
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWrite*",
      "dynamodb:CreateTable",
      "dynamodb:Update*",
      "dynamodb:PutItem"
    ]

    resources = [
      data.aws_dynamodb_table.bulk_email_users[0].arn,
    ]
  }
}

resource "aws_iam_policy" "bulk_email_users_dynamo_full_access" {
  count       = local.deploy_bulk_email_users_count
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing full permissions to the Dynamo Bulk Email Users table"

  policy = data.aws_iam_policy_document.bulk_email_users_full_access[0].json
}
