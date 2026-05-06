data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "client_registry_table" {
  name = "${var.environment}-client-registry"
}

data "aws_dynamodb_table" "common_passwords_table" {
  name = "${var.environment}-common-passwords"
}

data "aws_dynamodb_table" "account_modifiers_table" {
  name = "${var.environment}-account-modifiers"
}

data "aws_dynamodb_table" "email_check_results_table" {
  name = "${var.environment}-email-check-result"
}

data "aws_dynamodb_table" "international_sms_send_count_table" {
  name = "${var.environment}-international-sms-send-count"
}

data "aws_iam_policy_document" "check_email_fraud_block_read_dynamo_read_access_policy" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      data.aws_dynamodb_table.email_check_results_table.arn,
      "${data.aws_dynamodb_table.email_check_results_table.arn}/index/*",
    ]
  }
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
    resources = [
      local.user_profile_kms_key_arn,
      local.user_credentials_kms_key_arn,
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
    resources = [
      local.user_profile_kms_key_arn,
      local.user_credentials_kms_key_arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_user_delete_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${data.aws_dynamodb_table.user_credentials_table.arn}/index/*",
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
    resources = [local.client_registry_encryption_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_common_passwords_read_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",

    ]
    resources = [
      data.aws_dynamodb_table.common_passwords_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_am_account_modifiers_read_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",

    ]
    resources = [
      data.aws_dynamodb_table.account_modifiers_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_am_account_modifiers_delete_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DeleteItem",

    ]
    resources = [
      data.aws_dynamodb_table.account_modifiers_table.arn,
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

resource "aws_iam_policy" "dynamo_am_user_delete_access_policy" {
  name_prefix = "dynamo-account-management-user-delete-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing delete permissions to the Dynamo User tables"

  policy = data.aws_iam_policy_document.dynamo_user_delete_policy_document.json
}

resource "aws_iam_policy" "dynamo_am_user_write_access_policy" {
  name_prefix = "dynamo-account-management-user-write-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing write permissions to the Dynamo User tables"

  policy = data.aws_iam_policy_document.dynamo_user_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_common_passwords_read_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing read permissions to the Dynamo Common Passwords table"

  policy = data.aws_iam_policy_document.dynamo_common_passwords_read_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_am_account_modifiers_read_access_policy" {
  name_prefix = "dynamo-account-modifiers-read"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Account Modifiers table"

  policy = data.aws_iam_policy_document.dynamo_am_account_modifiers_read_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_am_account_modifiers_delete_access_policy" {
  name_prefix = "dynamo-account-modifiers-delete"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing delete permissions to the Dynamo Account Modifiers table"

  policy = data.aws_iam_policy_document.dynamo_am_account_modifiers_delete_access_policy_document.json
}

resource "aws_iam_policy" "check_email_fraud_block_read_dynamo_read_access_policy" {
  name_prefix = "dynamo-email-check-results-read-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Email Check Results table"

  policy = data.aws_iam_policy_document.check_email_fraud_block_read_dynamo_read_access_policy.json
}

data "aws_iam_policy_document" "dynamo_international_sms_send_count_read_write_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]

    resources = [
      data.aws_dynamodb_table.international_sms_send_count_table.arn,
      "${data.aws_dynamodb_table.international_sms_send_count_table.arn}/index/*",
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

    resources = [
      data.terraform_remote_state.shared.outputs.international_sms_send_count_encryption_key_arn,
    ]
  }
}

resource "aws_iam_policy" "dynamo_international_sms_send_count_read_write_access_policy" {
  name_prefix = "dynamo-international-sms-send-count-read-write-policy"
  path        = "/${var.environment}/am-shared/"
  description = "IAM policy for managing read and write permissions to the International SMS Send Count table"

  policy = data.aws_iam_policy_document.dynamo_international_sms_send_count_read_write_policy_document.json
}
