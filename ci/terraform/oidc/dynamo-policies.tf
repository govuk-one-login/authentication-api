data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "client_registry_table" {
  name = "${var.environment}-client-registry"
}

data "aws_dynamodb_table" "spot_credential_table" {
  name = "${var.environment}-spot-credential"
}

data "aws_iam_policy_document" "dynamo_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTable",
      "dynamodb:DeleteItem",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${data.aws_dynamodb_table.user_credentials_table.arn}/index/*",
      data.aws_dynamodb_table.client_registry_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_client_registration_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTable",
      "dynamodb:DeleteItem",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.client_registry_table.arn,
    ]
  }
}


data "aws_iam_policy_document" "dynamo_spot_write_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.spot_credential_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_spot_read_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:Get*",
    ]
    resources = [
      data.aws_dynamodb_table.spot_credential_table.arn,
    ]
  }
}

resource "aws_iam_policy" "dynamo_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing Dynamo connection for a lambda"

  policy = data.aws_iam_policy_document.dynamo_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_client_registry_write_policy" {
  name_prefix = "dynamo-client-registry-write-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo Client Registration table"

  policy = data.aws_iam_policy_document.dynamo_client_registration_policy_document.json
}

resource "aws_iam_policy" "dynamo_spot_write_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo SPOT credential table"

  policy = data.aws_iam_policy_document.dynamo_spot_write_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_spot_read_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo SPOT credential table"

  policy = data.aws_iam_policy_document.dynamo_spot_read_access_policy_document.json
}