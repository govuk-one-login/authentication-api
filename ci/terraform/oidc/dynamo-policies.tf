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

data "aws_dynamodb_table" "common_passwords_table" {
  name = "${var.environment}-common-passwords"
}

data "aws_dynamodb_table" "account_modifiers_table" {
  name = "${var.environment}-account-modifiers"
}

data "aws_dynamodb_table" "auth_code_store" {
  name = "${var.environment}-auth-code-store"
}

data "aws_dynamodb_table" "access_token_store" {
  name = "${var.environment}-access-token-store"
}

data "aws_dynamodb_table" "authentication_callback_userinfo_table" {
  name = "${var.environment}-authentication-callback-userinfo"
}

data "aws_dynamodb_table" "email_check_results_table" {
  name = "${var.environment}-email-check-result"
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
    resources = [local.user_profile_kms_key_arn]
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
    resources = [local.identity_credentials_encryption_key_arn]
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
    resources = [local.identity_credentials_encryption_key_arn]
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
    resources = [local.identity_credentials_encryption_key_arn]
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

  statement {
    sid    = "AllowAccessToDocAppCredentialTableKmsEncryptionKey"
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
      local.doc_app_credential_encryption_key_arn
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

  statement {
    sid    = "AllowAccessToDocAppCredentialTableKmsEncryptionKey"
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
      local.doc_app_credential_encryption_key_arn
    ]
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


data "aws_iam_policy_document" "dynamo_account_modifiers_read_access_policy_document" {
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

data "aws_iam_policy_document" "dynamo_account_modifiers_delete_access_policy_document" {
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

data "aws_iam_policy_document" "dynamo_account_modifiers_write_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.account_modifiers_table.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_access_token_write_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.access_token_store.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_access_token_delete_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.access_token_store.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_access_token_read_access_policy_document" {
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
      data.aws_dynamodb_table.access_token_store.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_authentication_callback_userinfo_write_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.authentication_callback_userinfo_table.arn,
      "${data.aws_dynamodb_table.authentication_callback_userinfo_table.arn}/index/*"
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
    resources = [local.authentication_callback_userinfo_encryption_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_authentication_callback_userinfo_read_policy_document" {
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
      data.aws_dynamodb_table.authentication_callback_userinfo_table.arn,
      "${data.aws_dynamodb_table.authentication_callback_userinfo_table.arn}/index/*",
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
    resources = [local.authentication_callback_userinfo_encryption_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_auth_code_store_write_access_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.auth_code_store.arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_auth_code_store_read_access_policy_document" {
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
      data.aws_dynamodb_table.auth_code_store.arn,
      "${data.aws_dynamodb_table.auth_code_store.arn}/index/*",
    ]
  }
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

resource "aws_iam_policy" "dynamo_common_passwords_read_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing read permissions to the Dynamo Common Passwords table"

  policy = data.aws_iam_policy_document.dynamo_common_passwords_read_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_account_modifiers_read_access_policy" {
  name_prefix = "dynamo-account-modifiers-read"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing read permissions to the Dynamo Account Modifiers table"

  policy = data.aws_iam_policy_document.dynamo_account_modifiers_read_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_account_modifiers_delete_access_policy" {
  name_prefix = "dynamo-account-modifiers-delete"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing delete permissions to the Dynamo Account Modifiers table"

  policy = data.aws_iam_policy_document.dynamo_account_modifiers_delete_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_account_modifiers_write_access_policy" {
  name_prefix = "dynamo-account-modifiers-write"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo Account Modifiers table"

  policy = data.aws_iam_policy_document.dynamo_account_modifiers_write_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_access_token_write_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing write permissions to the Dynamo access token store table"

  policy = data.aws_iam_policy_document.dynamo_access_token_write_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_access_token_read_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing read permissions to the Dynamo access token store table"

  policy = data.aws_iam_policy_document.dynamo_access_token_read_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_access_token_delete_access_policy" {
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing delete permissions to the Dynamo access token store table"

  policy = data.aws_iam_policy_document.dynamo_access_token_delete_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_authentication_callback_userinfo_read_policy" {
  name_prefix = "dynamo-authentication-callback-userinfo-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Callback User Info table"

  policy = data.aws_iam_policy_document.dynamo_authentication_callback_userinfo_read_policy_document.json
}

resource "aws_iam_policy" "dynamo_authentication_callback_userinfo_write_access_policy" {
  name_prefix = "dynamo-authentication-callback-userinfo-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the Dynamo Callback User Info table"

  policy = data.aws_iam_policy_document.dynamo_authentication_callback_userinfo_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_auth_code_store_write_access_policy" {
  name_prefix = "dynamo-auth-code-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the Dynamo Auth Code table (code used orch<->auth NOT RP<->orch)"

  policy = data.aws_iam_policy_document.dynamo_auth_code_store_write_access_policy_document.json
}

resource "aws_iam_policy" "dynamo_auth_code_store_read_access_policy" {
  name_prefix = "dynamo-auth-code-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Auth Code table (code used orch<->auth NOT RP<->orch)"

  policy = data.aws_iam_policy_document.dynamo_auth_code_store_read_access_policy_document.json
}

resource "aws_iam_policy" "check_email_fraud_block_read_dynamo_read_access_policy" {
  name_prefix = "dynamo-email-check-results-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the Dynamo Email Check Results table"

  policy = data.aws_iam_policy_document.check_email_fraud_block_read_dynamo_read_access_policy.json
}