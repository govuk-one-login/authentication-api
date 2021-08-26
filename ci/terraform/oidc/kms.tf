resource "aws_kms_key" "id_token_signing_key" {
  description             = "KMS signing key for ID tokens"
  deletion_window_in_days = 30
  key_usage               = "SIGN_VERIFY"
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
    ]
    resources = [
      aws_kms_key.id_token_signing_key.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_kms_signing_policy" {
  count = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing"

  policy = data.aws_iam_policy_document.kms_signing_policy_document[0].json
}


resource "aws_iam_policy" "lambda_kms_policy" {
  count = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.kms_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "lambda_kms" {
  count = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_kms_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "lambda_kms_signing_policy" {
  count = var.use_localstack ? 0 : 1
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_kms_signing_policy[0].arn
}
