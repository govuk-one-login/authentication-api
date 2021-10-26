locals {
  redis_key = "session"
}

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
  description             = "KMS key for parameter store"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.key_policy.json

  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  tags = local.default_tags
}

resource "aws_kms_alias" "parameter_store_key_alias" {
  name          = "alias/${var.environment}-lambda-parameter-store-encryption-key"
  target_key_id = aws_kms_key.parameter_store_key.id
}

resource "aws_ssm_parameter" "redis_master_host" {
  name   = "${var.environment}-${local.redis_key}-redis-master-host"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.sessions_store[0].primary_endpoint_address
}

resource "aws_ssm_parameter" "redis_replica_host" {
  name   = "${var.environment}-${local.redis_key}-redis-replica-host"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.sessions_store[0].reader_endpoint_address
}

resource "aws_ssm_parameter" "redis_tls" {
  name   = "${var.environment}-${local.redis_key}-redis-tls"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = var.use_localstack ? "false" : "true"
}

resource "aws_ssm_parameter" "redis_password" {
  name   = "${var.environment}-${local.redis_key}-redis-password"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = random_password.redis_password.result
}

resource "aws_ssm_parameter" "redis_port" {
  name   = "${var.environment}-${local.redis_key}-redis-port"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = var.use_localstack ? var.external_redis_port : aws_elasticache_replication_group.sessions_store[0].port
}

resource "aws_ssm_parameter" "password_pepper" {
  count  = var.password_pepper == null ? 0 : 1
  name   = "${var.environment}-${local.redis_key}-password-pepper"
  type   = "SecureString"
  key_id = aws_kms_alias.parameter_store_key_alias.id
  value  = var.password_pepper
}


data "aws_iam_policy_document" "redis_parameter_policy" {
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
    ]

    resources = [
      aws_ssm_parameter.redis_master_host.arn,
      aws_ssm_parameter.redis_replica_host.arn,
      aws_ssm_parameter.redis_tls.arn,
      aws_ssm_parameter.redis_password.arn,
      aws_ssm_parameter.redis_port.arn,
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
  policy      = data.aws_iam_policy_document.redis_parameter_policy.json
  path        = "/${var.environment}/redis/${local.redis_key}/"
  name_prefix = "parameter-store-policy"
}

resource "aws_iam_role_policy_attachment" "lambda_iam_role_parameters" {
  policy_arn = aws_iam_policy.parameter_policy.arn
  role       = aws_iam_role.lambda_iam_role.name
}

resource "aws_iam_role_policy_attachment" "token_lambda_iam_role_parameters" {
  policy_arn = aws_iam_policy.parameter_policy.arn
  role       = aws_iam_role.lambda_iam_role.name
}

resource "aws_iam_role_policy_attachment" "dynamo_sqs_lambda_iam_role_parameters" {
  policy_arn = aws_iam_policy.parameter_policy.arn
  role       = aws_iam_role.lambda_iam_role.name
}

data "aws_iam_policy_document" "pepper_parameter_policy" {
  count = var.password_pepper == null ? 0 : 1
  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
    ]

    resources = [
      aws_ssm_parameter.password_pepper.arn
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

resource "aws_iam_policy" "pepper_parameter_policy" {
  policy      = data.aws_iam_policy_document.pepper_parameter_policy.json
  path        = "/${var.environment}/lambda-parameters/"
  name_prefix = "pepper-parameter-store-policy"
}

resource "aws_iam_role_policy_attachment" "lambda_iam_role_pepper_parameters" {
  policy_arn = aws_iam_policy.pepper_parameter_policy.arn
  role       = aws_iam_role.lambda_iam_role.name
}
