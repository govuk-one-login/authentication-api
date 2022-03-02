data "aws_iam_policy_document" "key_policy" {
  policy_id = "key-policy-ssm"
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
}

resource "aws_kms_key" "parameter_store_key" {
  description             = "KMS key for delivery receipts parameter store"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.key_policy.json

  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  tags = local.default_tags
}

resource "aws_kms_alias" "parameter_store_key_alias" {
  name          = "alias/${var.environment}-delivert-receipts-lambda-parameter-store-encryption-key"
  target_key_id = aws_kms_key.parameter_store_key.id
}

resource "aws_ssm_parameter" "notify_callback_bearer_token" {
  name   = "${var.environment}-notify-callback-bearer-token"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = random_string.notify_bearer_token.result
}

resource "random_string" "notify_bearer_token" {
  length = 64

  min_lower   = 3
  min_numeric = 3
  min_special = 3
  min_upper   = 3
}

data "aws_iam_policy_document" "bearer_token_parameter_policy" {
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]

    resources = [
      aws_ssm_parameter.notify_callback_bearer_token.arn,
    ]
  }
  statement {
    sid    = "AllowDecryptOfParameters"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      aws_kms_alias.parameter_store_key_alias.arn,
      aws_kms_key.parameter_store_key.arn
    ]
  }
}

resource "aws_iam_policy" "parameter_policy" {
  policy      = data.aws_iam_policy_document.bearer_token_parameter_policy.json
  path        = "/${var.environment}/notify-bearer-token/"
  name_prefix = "parameter-store-policy"
}