data "aws_dynamodb_table" "common_passwords" {
  name = "${var.environment}-common-passwords"
}

data "aws_iam_policy_document" "common_passwords_dynamo_full_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGet*",
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWrite*",
      "dynamodb:CreateTable",
      "dynamodb:Delete*",
      "dynamodb:Update*",
      "dynamodb:PutItem"
    ]

    resources = [
      data.aws_dynamodb_table.common_passwords.arn,
    ]
  }
}

resource "aws_iam_policy" "common_passwords_dynamo_full_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing full permissions to the Dynamo Common Passwords table"

  policy = data.aws_iam_policy_document.common_passwords_dynamo_full_access.json
}