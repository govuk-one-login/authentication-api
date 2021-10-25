resource "aws_kms_key" "id_token_signing_key" {
  description              = "KMS signing key for ID tokens"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  tags = local.default_tags
}

resource "aws_kms_alias" "id_token_signing_key_alias" {
  name          = "alias/${var.environment}-id-token-signing-key-alias"
  target_key_id = aws_kms_key.id_token_signing_key.key_id
}

data "aws_iam_policy_document" "kms_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.id_token_signing_key.arn,
    ]
  }
}

data "aws_iam_policy_document" "kms_signing_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.id_token_signing_key.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_kms_signing_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing"

  policy = data.aws_iam_policy_document.kms_signing_policy_document[0].json
}


resource "aws_iam_policy" "lambda_kms_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.kms_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "lambda_kms" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_kms_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "lambda_kms_signing_policy" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_kms_signing_policy[0].arn
}

# Audit signing key

resource "aws_kms_key" "audit_payload_signing_key" {
  description              = "KMS signing key for audit payloads"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  tags = local.default_tags
}

resource "aws_kms_alias" "audit_payload_signing_key_alias" {
  name          = "alias/${var.environment}-audit-payload-signing-key-alias"
  target_key_id = aws_kms_key.audit_payload_signing_key.key_id
}

data "aws_iam_policy_document" "audit_payload_kms_signing_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToKmsAuditSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:Verify"
    ]
    resources = [
      aws_kms_key.audit_payload_signing_key.arn,
    ]
  }
}

resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-audit-payload-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.audit_payload_kms_signing_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "attach_audit_signing_key_policy_default" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "attach_audit_signing_key_policy_token" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "attach_audit_signing_key_policy_dynamo" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn
}

# Cloudwatch Log Encryption
data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "cloudwatch" {
  policy_id = "key-policy-cloudwatch"
  statement {
    sid = "Enable IAM User Permissions for root user"
    actions = [
      "kms:*",
    ]
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          data.aws_caller_identity.current.account_id
        )
      ]
    }
    resources = ["*"]
  }
  statement {
    sid = "AllowCloudWatchLogs"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:Describe*"
    ]
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        format(
          "logs.%s.amazonaws.com",
          data.aws_region.current.name
        )
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "cloudwatch_log_encryption" {
  description             = "KMS key for Cloudwatch logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudwatch.json

  tags = local.default_tags
}

resource "aws_kms_key" "lambda_env_vars_encryption_key" {
  description              = "KMS encryption key for lambda environment variables"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  tags = local.default_tags
}

resource "aws_kms_alias" "lambda_env_vars_encryption_key_alias" {
  name          = "alias/${var.environment}-lambda-env-vars-encryption-key-alias"
  target_key_id = aws_kms_key.lambda_env_vars_encryption_key.key_id
}

data "aws_iam_policy_document" "lambda_env_vars_encryption_key_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToLambdaEnvVarsKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:GetPublicKey"
    ]
    resources = [
      aws_kms_key.lambda_env_vars_encryption_key.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_env_vars_encryption_kms_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-lambda-env-vars-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda environment variable encryption"

  policy = data.aws_iam_policy_document.lambda_env_vars_encryption_key_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "lambda_env_vars_encryption_kms_policy" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_env_vars_encryption_kms_policy[0].arn
}