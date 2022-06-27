resource "random_password" "hmac_key" {
  length = 32

  override_special = "!&#$^<>-"
  min_lower        = 3
  min_numeric      = 3
  min_special      = 3
  min_upper        = 3
}

data "aws_iam_policy_document" "key_policy" {
  count = var.txma_obfuscation_secret_arn == "" ? 1 : 0

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

resource "aws_kms_key" "secrets_manager_key" {
  count = var.txma_obfuscation_secret_arn == "" ? 1 : 0

  description             = "KMS key for secrets manager"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.key_policy[0].json

  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  tags = local.default_tags
}

resource "aws_secretsmanager_secret" "hmac_secret" {
  count = var.txma_obfuscation_secret_arn == "" ? 1 : 0

  name_prefix = "hmac-secret-key-"
  kms_key_id  = aws_kms_key.secrets_manager_key[0].id
}

resource "aws_secretsmanager_secret_version" "hmac_secret" {
  count = var.txma_obfuscation_secret_arn == "" ? 1 : 0

  secret_id     = aws_secretsmanager_secret.hmac_secret[0].id
  secret_string = random_password.hmac_key.result
}

resource "aws_iam_policy" "txma_secrets_policy" {
  name_prefix = "txma-hmac-key-secret-"
  path        = "/${var.environment}/fraud-realtime-logging/"
  description = "IAM policy for a lambda needing to access the HMAC key secret in TXMA secrets manager"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue"
      ]

      Resource = [
        var.txma_obfuscation_secret_arn == "" ? aws_secretsmanager_secret.hmac_secret[0].arn : var.txma_obfuscation_secret_arn,
      ]
      }, {
      Effect = "Allow"
      Action = [
        "kms:Decrypt"
      ]

      Resource = [
        var.txma_obfuscation_secret_arn == "" ? aws_kms_key.secrets_manager_key[0].arn : var.txma_obfuscation_secret_kms_key_arn,
      ]
    }]
  })

  lifecycle {
    create_before_destroy = true
  }
}

module "fraud_realtime_logging_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "fraud-realtime-logging"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.fraud_realtime_logging_audit_payload_kms_verification.arn,
    aws_iam_policy.txma_secrets_policy.arn,
  ]
}

resource "aws_iam_policy" "fraud_realtime_logging_audit_payload_kms_verification" {
  name_prefix = "payload-kms-verification-"
  path        = "/${var.environment}/fraud-realtime-logging/"
  description = "IAM policy for a lambda needing to verify payload signatures"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:Verify"
      ]

      Resource = [
        local.audit_signing_key_arn,
      ]
    }]
  })
}

resource "aws_lambda_function" "fraud_realtime_logging_lambda" {
  function_name = "${var.environment}-fraud-realtime-logging-lambda"
  role          = module.fraud_realtime_logging_role.arn
  handler       = "uk.gov.di.authentication.audit.lambda.CounterFraudAuditLambda::handleRequest"
  timeout       = 30
  memory_size   = var.lambda_memory_size
  publish       = true

  tracing_config {
    mode = "Active"
  }

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.audit_processor_release_zip.key
  s3_object_version = aws_s3_bucket_object.audit_processor_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = {
      AUDIT_SIGNING_KEY_ALIAS     = local.audit_signing_key_alias_name
      LOCALSTACK_ENDPOINT         = var.use_localstack ? var.localstack_endpoint : null
      TXMA_OBFUSCATION_SECRET_ARN = var.txma_obfuscation_secret_arn == "" ? aws_secretsmanager_secret.hmac_secret[0].arn : var.txma_obfuscation_secret_arn
    }
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  runtime = "java11"

  tags = local.default_tags
}

resource "aws_sns_topic_subscription" "fraud_realtime_logging_lambda_subscription" {
  topic_arn = data.aws_sns_topic.event_stream.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.fraud_realtime_logging_lambda.arn
}

resource "aws_lambda_permission" "sns_can_execute_subscriber_fraud_realtime_logging_lambda" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fraud_realtime_logging_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = data.aws_sns_topic.event_stream.arn
}

resource "aws_cloudwatch_log_group" "fraud_realtime_logging_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.fraud_realtime_logging_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = local.cloudwatch_key_arn
  retention_in_days = 1 # We shouldn't hold onto this for long

  depends_on = [
    aws_lambda_function.fraud_realtime_logging_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "fraud_realtime_logging_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.fraud_realtime_logging_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.fraud_realtime_logging_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_lambda_alias" "fraud_realtime_logging_lambda_active" {
  name             = "${aws_lambda_function.fraud_realtime_logging_lambda.function_name}-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.fraud_realtime_logging_lambda.arn
  function_version = aws_lambda_function.fraud_realtime_logging_lambda.version
}