data "aws_ssm_parameter" "redis_master_host" {
  name = "${var.environment}-${local.redis_key}-redis-master-host"
}

data "aws_ssm_parameter" "redis_replica_host" {
  name = "${var.environment}-${local.redis_key}-redis-replica-host"
}

data "aws_ssm_parameter" "redis_tls" {
  name = "${var.environment}-${local.redis_key}-redis-tls"
}

data "aws_ssm_parameter" "redis_password" {
  name = "${var.environment}-${local.redis_key}-redis-password"
}

data "aws_ssm_parameter" "redis_port" {
  name = "${var.environment}-${local.redis_key}-redis-port"
}

data "aws_iam_policy_document" "redis_parameter_policy" {
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]

    resources = [
      data.aws_ssm_parameter.redis_master_host.arn,
      data.aws_ssm_parameter.redis_replica_host.arn,
      data.aws_ssm_parameter.redis_tls.arn,
      data.aws_ssm_parameter.redis_password.arn,
      data.aws_ssm_parameter.redis_port.arn,
    ]
  }
  statement {
    sid    = "AllowDecryptOfParameters"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      local.lambda_parameter_encryption_alias_id,
      local.lambda_parameter_encryption_key_id
    ]
  }
}

resource "aws_iam_policy" "redis_parameter_policy" {
  policy      = data.aws_iam_policy_document.redis_parameter_policy.json
  path        = "/${var.environment}/redis/${local.redis_key}/"
  name_prefix = "parameter-store-policy"
}

## Password pepper policy

data "aws_ssm_parameter" "password_pepper" {
  name = "${var.environment}-password-pepper"
}

data "aws_iam_policy_document" "pepper_parameter_policy" {
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]

    resources = [
      data.aws_ssm_parameter.password_pepper.arn
    ]
  }
  statement {
    sid    = "AllowDecryptOfParameters"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      local.lambda_parameter_encryption_alias_id,
      local.lambda_parameter_encryption_key_id
    ]
  }
}

resource "aws_iam_policy" "pepper_parameter_policy" {
  policy      = data.aws_iam_policy_document.pepper_parameter_policy[0].json
  path        = "/${var.environment}/lambda-parameters/"
  name_prefix = "pepper-parameter-store-policy"
}