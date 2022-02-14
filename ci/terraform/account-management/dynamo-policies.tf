data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "client_registry_table" {
  name = "${var.environment}-client-registry"
}

data "aws_iam_policy_document" "dynamo_user_write_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${data.aws_dynamodb_table.user_credentials_table.arn}/index/*",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_user_read_policy_document" {
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
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${data.aws_dynamodb_table.user_credentials_table.arn}/index/*",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_client_registration_read_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [
      data.aws_dynamodb_table.client_registry_table.arn,
    ]
  }
}

resource "aws_iam_policy" "dynamo_am_client_registry_read_access_policy" {
  name_prefix = "dynamo-account-management-client-registry-read-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Client Registration table"

  policy = data.aws_iam_policy_document.dynamo_client_registration_read_policy_document.json
}

resource "aws_iam_policy" "dynamo_am_user_read_access_policy" {
  name_prefix = "dynamo-account-management-user-read-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing read permissions to the Dynamo User tables"

  policy = data.aws_iam_policy_document.dynamo_user_read_policy_document.json
}

resource "aws_iam_policy" "dynamo_am_user_write_access_policy" {
  name_prefix = "dynamo-account-management-user-write-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing write permissions to the Dynamo User tables"

  policy = data.aws_iam_policy_document.dynamo_user_write_policy_document.json
}