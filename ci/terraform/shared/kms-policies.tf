resource "aws_iam_policy" "account_modifiers_encryption_key_kms_policy" {
  name        = "${var.environment}-account-modifiers-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the account modifiers table"

  policy = data.aws_iam_policy_document.account_modifiers_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "account_modifiers_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToAccountModifiersTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.account_modifiers_table_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "common_passwords_encryption_key_kms_policy" {
  name        = "${var.environment}-common-passwords-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the common passwords table"

  policy = data.aws_iam_policy_document.common_passwords_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "common_passwords_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToCommonPasswordsTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.common_passwords_table_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "client_registry_encryption_key_kms_policy" {
  name        = "${var.environment}-client-registry-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the client registry table"

  policy = data.aws_iam_policy_document.client_registry_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "client_registry_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToClientRegistryTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.client_registry_table_encryption_key.arn
    ]
  }
}


resource "aws_iam_policy" "user_credentials_encryption_key_kms_policy" {
  name        = "${var.environment}-user-credentials-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the user credentials table"

  policy = data.aws_iam_policy_document.user_credentials_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "user_credentials_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToUserCredentialsTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.user_credentials_table_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "user_profile_encryption_key_kms_policy" {
  name        = "${var.environment}-user-profile-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the user profile table"

  policy = data.aws_iam_policy_document.user_profile_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "user_profile_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToUserProfileTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.user_profile_table_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "email_check_results_encryption_key_kms_policy" {
  name        = "${var.environment}-email-check-results-table-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS encryption of the email check results table"

  policy = data.aws_iam_policy_document.email_check_results_encryption_key_kms_policy_document.json
}

data "aws_iam_policy_document" "email_check_results_encryption_key_kms_policy_document" {
  statement {
    sid    = "AllowAccessToEmailCheckResultsTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:*",
    ]
    resources = [
      aws_kms_key.email_check_result_encryption_key.arn
    ]
  }
}
