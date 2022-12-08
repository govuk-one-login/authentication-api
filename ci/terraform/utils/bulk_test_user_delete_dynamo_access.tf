data "aws_iam_policy_document" "user_profile_dynamo_delete_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Scan",
      "dynamodb:Delete*"
    ]

    resources = [
      data.aws_dynamodb_table.user_profile.arn,
    ]
  }
}

resource "aws_iam_policy" "user_profile_dynamo_delete_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing delete access to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.user_profile_dynamo_delete_access.json
}

data "aws_dynamodb_table" "user_credentials" {
  name = "${var.environment}-user-credentials"
}

data "aws_iam_policy_document" "user_credentials_dynamo_delete_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Scan",
      "dynamodb:Delete*"
    ]

    resources = [
      data.aws_dynamodb_table.user_credentials.arn,
    ]
  }
}

resource "aws_iam_policy" "user_credentials_dynamo_delete_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing delete access to the Dynamo User Credentials table"

  policy = data.aws_iam_policy_document.user_credentials_dynamo_delete_access.json
}
