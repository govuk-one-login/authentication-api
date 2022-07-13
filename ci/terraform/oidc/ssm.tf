data "aws_iam_policy" "redis_parameter_policy" {
  arn = local.redis_ssm_parameter_policy
}

resource "aws_iam_policy" "redis_parameter_policy" {
  policy      = data.aws_iam_policy.redis_parameter_policy.policy
  path        = "/${var.environment}/redis/${local.redis_key}/"
  name_prefix = "parameter-store-policy"
}

## Password pepper policy

data "aws_iam_policy" "pepper_parameter_policy" {
  arn = local.pepper_ssm_parameter_policy
}

resource "aws_iam_policy" "pepper_parameter_policy" {
  policy      = data.aws_iam_policy.pepper_parameter_policy.policy
  path        = "/${var.environment}/lambda-parameters/"
  name_prefix = "pepper-parameter-store-policy"
}

## IPV capacity parameter

resource "aws_ssm_parameter" "ipv-capacity" {
  name  = "${var.environment}-ipv-capacity"
  type  = "String"
  value = var.ipv_capacity_allowed ? "1" : "0"

  lifecycle {
    ignore_changes = [
      value
    ]
  }
}

data "aws_iam_policy_document" "ipv_capacity_parameter_policy_document" {
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]

    resources = [
      aws_ssm_parameter.ipv-capacity.arn
    ]
  }
}

resource "aws_iam_policy" "ipv_capacity_parameter_policy" {
  policy      = data.aws_iam_policy_document.ipv_capacity_parameter_policy_document.json
  path        = "/${var.environment}/lambda-parameters/"
  name_prefix = "ipv-capacity-parameter-store-policy"
}

## IPV public encryption key parameter

resource "aws_ssm_parameter" "ipv_public_encryption_key" {
  name  = "${var.environment}-ipv-public-encryption-key"
  type  = "String"
  value = var.ipv_auth_public_encryption_key
}

data "aws_iam_policy_document" "ipv_public_encryption_key_parameter_policy_document" {
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]

    resources = [
      aws_ssm_parameter.ipv_public_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "ipv_public_encryption_key_parameter_policy" {
  policy      = data.aws_iam_policy_document.ipv_public_encryption_key_parameter_policy_document.json
  path        = "/${var.environment}/lambda-parameters/"
  name_prefix = "ipv-public-encryption-key-parameter-store-policy"
}

## SPOT  

resource "aws_ssm_parameter" "spot_account_number" {
  name  = "${var.environment}-spot-account-number"
  type  = "String"
  value = var.spot_account_number
}

resource "aws_ssm_parameter" "spot_response_queue_arn" {
  name  = "${var.environment}-spot-response-queue-arn"
  type  = "String"
  value = var.spot_response_queue_arn
}

resource "aws_ssm_parameter" "spot_response_queue_kms_arn" {
  name  = "${var.environment}-spot-response-queue-kms-arn"
  type  = "String"
  value = var.spot_response_queue_kms_arn
}
