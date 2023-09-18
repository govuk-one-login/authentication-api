data "aws_iam_policy_document" "delivery_receipts_dynamo_update_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
    ]

    resources = [
      data.aws_dynamodb_table.bulk_email_users_table[0].arn,
      "${data.aws_dynamodb_table.bulk_email_users_table[0].arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "delivery_receipts_dynamo_update_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing update access for the Delivery Receipts lambda to the Dynamo Bulk Email Users table"

  policy = data.aws_iam_policy_document.delivery_receipts_dynamo_update_access[0].json
}

data "aws_iam_policy_document" "delivery_receipts_dynamo_read_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
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
}

resource "aws_iam_policy" "delivery_receipts_dynamo_read_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing read access for the Bulk User Email Send lambda to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.delivery_receipts_dynamo_read_access[0].json
}