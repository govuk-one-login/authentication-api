data "aws_iam_policy_document" "user_profile_dynamo_write_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:BatchWrite*",
      "dynamodb:Update*",
      "dynamodb:PutItem"
    ]

    resources = [
      data.aws_dynamodb_table.user_profile.arn,
    ]
  }
}

resource "aws_iam_policy" "user_profile_dynamo_write_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing write access to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.user_profile_dynamo_write_access.json
}

data "aws_iam_policy_document" "user_credentials_dynamo_write_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:BatchWrite*",
      "dynamodb:Update*",
      "dynamodb:PutItem"
    ]

    resources = [
      data.aws_dynamodb_table.user_credentials.arn,
    ]
  }
}

resource "aws_iam_policy" "user_credentials_dynamo_write_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing write access to the Dynamo User Credentials table"

  policy = data.aws_iam_policy_document.user_credentials_dynamo_write_access.json
}
