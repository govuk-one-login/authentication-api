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

data "aws_dynamodb_table" "email_check_results_table" {
  name = "${var.environment}-email-check-result"
}

data "aws_dynamodb_table" "authentication_attempt_table" {
  name = "${var.environment}-authentication-attempt"
}

data "aws_dynamodb_table" "auth_session_table" {
  name = "${var.environment}-auth-session"
}

data "aws_dynamodb_table" "id_reverification_state_table" {
  name = "${var.environment}-id-reverification-state"
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
    resources = [local.user_profile_kms_key_arn, local.user_credentials_kms_key_arn]
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
    resources = [local.user_profile_kms_key_arn, local.user_credentials_kms_key_arn]
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

data "aws_iam_policy_document" "dynamo_authentication_attempt_delete_policy_document" {
  statement {
    sid    = "AllowDelete"
    effect = "Allow"

    actions = [
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.authentication_attempt_table.arn,
      "${data.aws_dynamodb_table.authentication_attempt_table.arn}/index/*",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_authentication_attempt_write_policy_document" {
  statement {
    sid    = "AllowWrite"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.authentication_attempt_table.arn,
      "${data.aws_dynamodb_table.authentication_attempt_table.arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowEncryption"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [local.authentication_attempt_kms_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_authentication_attempt_read_policy_document" {
  statement {
    sid    = "AllowRead"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      data.aws_dynamodb_table.authentication_attempt_table.arn,
      "${data.aws_dynamodb_table.authentication_attempt_table.arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowDecryption"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [local.authentication_attempt_kms_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_auth_session_delete_policy_document" {
  statement {
    sid    = "AllowDelete"
    effect = "Allow"

    actions = [
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.auth_session_table.arn,
      "${data.aws_dynamodb_table.auth_session_table.arn}/index/*",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_auth_session_write_policy_document" {
  statement {
    sid    = "AllowWrite"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.auth_session_table.arn,
      "${data.aws_dynamodb_table.auth_session_table.arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowEncryption"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [local.auth_session_table_encryption_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_auth_session_read_policy_document" {
  statement {
    sid    = "AllowRead"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      data.aws_dynamodb_table.auth_session_table.arn,
      "${data.aws_dynamodb_table.auth_session_table.arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowDecryption"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [local.auth_session_table_encryption_key_arn]
  }
}

// This is required because we've reached the managed polices per role quota limit (20)
// Ticket raised to requst quota increase (ATO-1056)
data "aws_iam_policy_document" "dynamo_auth_session_read_write_policy_document" {
  statement {
    sid    = "AllowReadAndWrite"
    effect = "Allow"

    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      data.aws_dynamodb_table.auth_session_table.arn,
      "${data.aws_dynamodb_table.auth_session_table.arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowEncryptionAndDecryption"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [local.auth_session_table_encryption_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_orch_session_encryption_key_cross_account_decrypt_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchSessionEncryptionKeyCrossAccountDecryptAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      var.orch_session_table_encryption_key_arn,
    ]
  }
}


data "aws_iam_policy_document" "dynamo_orch_session_encryption_key_cross_account_encrypt_decrypt_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchSessionEncryptionKeyCrossAccountEncryptAccess"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
    ]
    resources = [
      var.orch_session_table_encryption_key_arn,
    ]
  }
}


data "aws_iam_policy_document" "dynamo_orch_session_cross_account_read_and_delete_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchSessionCrossAccountReadAndDeleteAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:DeleteItem",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Orch-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_session_cross_account_read_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1

  statement {
    sid    = "AllowOrchSessionCrossAccountReadAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Orch-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_session_cross_account_read_write_delete_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1

  statement {
    sid    = "AllowOrchSessionCrossAccountReadWriteDeleteAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Orch-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_session_cross_account_write_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1

  statement {
    sid    = "AllowOrchSessionCrossAccountWriteAccess"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Orch-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_session_cross_account_delete_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchSessionCrossAccountDeleteAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DeleteItem",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Orch-Session",
    ]
  }
}


data "aws_iam_policy_document" "dynamo_orch_client_session_cross_account_read_and_delete_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchClientSessionCrossAccountReadAndDeleteAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:DeleteItem",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Client-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_client_session_cross_account_read_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchClientSessionCrossAccountReadAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Client-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_client_session_cross_account_delete_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchClientSessionCrossAccountDeleteAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DeleteItem"
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Client-Session",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_client_session_encryption_key_cross_account_decrypt_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1
  statement {
    sid    = "AllowOrchClientSessionEncryptionKeyCrossAccountDecryptAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      var.orch_client_session_table_encryption_key_arn,
    ]
  }
}

data "aws_iam_policy_document" "dynamo_orch_identity_credentials_cross_account_read_access_policy_document" {
  count = var.is_orch_stubbed ? 0 : 1

  statement {
    sid    = "AllowOrchIdentityCredentialsEncryptionKeyCrossAccountDecryptAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      var.orch_identity_credentials_table_encryption_key_arn,
    ]
  }

  statement {
    sid    = "AllowOrchIdentityCredentialsCrossAccountReadAccess"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-Orch-Identity-Credentials",
    ]
  }
}

data "aws_iam_policy_document" "dynamo_id_reverification_state_write_policy_document" {
  statement {
    sid    = "AllowWrite"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.id_reverification_state_table.arn
    ]
  }

  statement {
    sid    = "AllowEncryption"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [local.id_reverification_state_key_arn]
  }
}

data "aws_iam_policy_document" "dynamo_id_reverification_state_read_policy_document" {
  statement {
    sid    = "AllowRead"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]
    resources = [
      data.aws_dynamodb_table.id_reverification_state_table.arn
    ]
  }

  statement {
    sid    = "AllowDecryption"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [local.id_reverification_state_key_arn]
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

resource "aws_iam_policy" "dynamo_authentication_attempt_write_policy" {
  name_prefix = "dynamo-authentication-attempt-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the authentication attempts table"

  policy = data.aws_iam_policy_document.dynamo_authentication_attempt_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_authentication_attempt_read_policy" {
  name_prefix = "dynamo-authentication-attempt-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the authentication attempts table"

  policy = data.aws_iam_policy_document.dynamo_authentication_attempt_read_policy_document.json
}

resource "aws_iam_policy" "dynamo_authentication_attempt_delete_policy" {
  name_prefix = "dynamo-authentication-attempt-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing delete permissions to the authentication attempts table"

  policy = data.aws_iam_policy_document.dynamo_authentication_attempt_delete_policy_document.json
}

resource "aws_iam_policy" "dynamo_auth_session_write_policy" {
  name_prefix = "dynamo-auth-session-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the auth session table"

  policy = data.aws_iam_policy_document.dynamo_auth_session_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_auth_session_read_policy" {
  name_prefix = "dynamo-auth-session-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the auth session table"

  policy = data.aws_iam_policy_document.dynamo_auth_session_read_policy_document.json
}

// This is required because we've reached the managed polices per role quota limit (20)
// Ticket raised to requst quota increase (ATO-1056)
resource "aws_iam_policy" "dynamo_auth_session_read_write_policy" {
  name_prefix = "dynamo-auth-session-read-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read and write permissions to the auth session table"

  policy = data.aws_iam_policy_document.dynamo_auth_session_read_write_policy_document.json
}

resource "aws_iam_policy" "dynamo_auth_session_delete_policy" {
  name_prefix = "dynamo-auth-session-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing delete permissions to the auth session table"

  policy = data.aws_iam_policy_document.dynamo_auth_session_delete_policy_document.json
}

resource "aws_iam_policy" "dynamo_orch_session_encryption_key_cross_account_decrypt_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-encryption-key-cross-account-decrypt-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing decrypt and describe permissions to the orch session table's KMS encryption key"

  policy = data.aws_iam_policy_document.dynamo_orch_session_encryption_key_cross_account_decrypt_policy_document[count.index].json
}


resource "aws_iam_policy" "dynamo_orch_client_session_encryption_key_cross_account_decrypt_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-client-session-encryption-key-cross-account-decrypt-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing decrypt and describe permissions to the orch client session table's KMS encryption key"

  policy = data.aws_iam_policy_document.dynamo_orch_client_session_encryption_key_cross_account_decrypt_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_orch_session_encryption_key_cross_account_encrypt_decrypt_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-encryption-key-cross-account-encrypt-decrypt-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing encrypt and decrypt permissions to the orch session table's KMS encryption key"

  policy = data.aws_iam_policy_document.dynamo_orch_session_encryption_key_cross_account_encrypt_decrypt_policy_document[count.index].json
}


resource "aws_iam_policy" "dynamo_orch_session_cross_account_read_and_delete_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-cross-account-read-and-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read and delete permissions to the orch session table"

  policy = data.aws_iam_policy_document.dynamo_orch_session_cross_account_read_and_delete_access_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_orch_session_cross_account_read_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-cross-account-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the orch session table"

  policy = data.aws_iam_policy_document.dynamo_orch_session_cross_account_read_access_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_orch_session_cross_account_write_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-cross-account-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the orch session table"

  policy = data.aws_iam_policy_document.dynamo_orch_session_cross_account_write_access_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_orch_session_cross_account_read_write_delete_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-cross-account-read-write-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read, write and delete permissions to the orch session table"

  policy = data.aws_iam_policy_document.dynamo_orch_session_cross_account_read_write_delete_access_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_orch_session_cross_account_delete_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-session-cross-account-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing delete permissions to the orch session table"

  policy = data.aws_iam_policy_document.dynamo_orch_session_cross_account_delete_access_policy_document[count.index].json
}


resource "aws_iam_policy" "dynamo_orch_client_session_cross_account_read_and_delete_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-client-session-cross-account-read-and-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read and delete permissions to the orch client session table"

  policy = data.aws_iam_policy_document.dynamo_orch_client_session_cross_account_read_and_delete_access_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_orch_client_session_cross_account_read_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-client-session-cross-account-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the orch client session table"

  policy = data.aws_iam_policy_document.dynamo_orch_client_session_cross_account_read_access_policy_document[count.index].json
}


resource "aws_iam_policy" "dynamo_orch_client_session_cross_account_delete_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-client-session-cross-account-delete-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing delete permissions to the orch client session table"

  policy = data.aws_iam_policy_document.dynamo_orch_client_session_cross_account_delete_access_policy_document[count.index].json
}


resource "aws_iam_policy" "dynamo_orch_identity_credentials_cross_account_read_access_policy" {
  count = var.is_orch_stubbed ? 0 : 1

  name_prefix = "dynamo-orch-identity-credentials-cross-account-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the orch identity credentials table"

  policy = data.aws_iam_policy_document.dynamo_orch_identity_credentials_cross_account_read_access_policy_document[count.index].json
}

resource "aws_iam_policy" "dynamo_id_reverification_state_write_policy" {
  name_prefix = "dynamo-id-reverification-state-write-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing write permissions to the ${var.environment}-id-reverification-state table"

  policy = data.aws_iam_policy_document.dynamo_id_reverification_state_write_policy_document.json
}


resource "aws_iam_policy" "dynamo_id_reverification_state_read_policy" {
  name_prefix = "dynamo-id-reverification-state-read-policy"
  path        = "/${var.environment}/oidc-shared/"
  description = "IAM policy for managing read permissions to the ${var.environment}-id-reverification-state table"

  policy = data.aws_iam_policy_document.dynamo_id_reverification_state_read_policy_document.json
}
