data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "client_registry_table" {
  name = "${var.environment}-client-registry"
}

data "aws_dynamodb_table" "identity_credentials_table" {
  name = "${var.environment}-identity-credentials"
}

data "aws_dynamodb_table" "doc_app_cri_credential_table" {
  name = "${var.environment}-doc-app-credential"
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
      data.aws_dynamodb_table.doc_app_cri_credential_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${data.aws_dynamodb_table.user_credentials_table.arn}/index/*",
      "${data.aws_dynamodb_table.doc_app_cri_credential_table.arn}/index/*",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_client_registration_write_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.client_registry_table.arn,
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

data "aws_iam_policy_document" "dynamo_identity_write_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.identity_credentials_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_identity_delete_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.identity_credentials_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_identity_read_access_policy_document" {
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
      data.aws_dynamodb_table.identity_credentials_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_doc_app_write_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.doc_app_cri_credential_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_doc_app_read_access_policy_document" {
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
      data.aws_dynamodb_table.doc_app_cri_credential_table.arn,
    ]
  }
}

resource "aws_iam_policy" "dynamo_client_registry_write_access_policy" {
  name_prefix = "dynamo-client-registry-write-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo Client Registration table"

  policy = data.aws_iam_policy_document.dynamo_client_registration_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_client_registry_read_access_policy" {
  name_prefix = "dynamo-client-registry-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Client Registration table"

  policy = data.aws_iam_policy_document.dynamo_client_registration_read_policy_document.json
}

resource "aws_iam_policy" "dynamo_user_read_access_policy" {
  name_prefix = "dynamo-user-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the Dynamo User tables"

  policy = data.aws_iam_policy_document.dynamo_user_read_policy_document.json
}

resource "aws_iam_policy" "dynamo_user_write_access_policy" {
  name_prefix = "dynamo-user-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the Dynamo User tables"

  policy = data.aws_iam_policy_document.dynamo_user_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_identity_credentials_write_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo Identity credentials table"

  policy = data.aws_iam_policy_document.dynamo_identity_write_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_identity_credentials_read_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing read permissions to the Dynamo Identity credentials table"

  policy = data.aws_iam_policy_document.dynamo_identity_read_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_identity_credentials_delete_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing delete permissions to the Dynamo Identity credentials table"

  policy = data.aws_iam_policy_document.dynamo_identity_delete_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_doc_app_write_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo Doc App CRI credential table"

  policy = data.aws_iam_policy_document.dynamo_doc_app_write_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_doc_app_read_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing read permissions to the Dynamo Doc App CRI credential table"

  policy = data.aws_iam_policy_document.dynamo_doc_app_read_access_policy_document.json
}