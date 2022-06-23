resource "aws_s3_bucket" "fraud_replay_bucket" {
  bucket = "${var.environment}-fraud-replay-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = false
  }

  tags = local.default_tags
}

resource "aws_s3_bucket_public_access_block" "replay_bucket_access" {
  bucket                  = aws_s3_bucket.fraud_replay_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "replay_bucket_s3_access" {
  name_prefix = "lambda-s3-access"
  path        = "/${var.environment}/replay-storage/"
  description = "IAM policy for managing s3 access to replay lambda"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:DeleteObject",
      ]

      Resource = [
        aws_s3_bucket.fraud_replay_bucket.arn,
        "${aws_s3_bucket.fraud_replay_bucket.arn}/*"
      ]
    }]
  })
}

module "fraud_realtime_logging_replay_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "fraud-realtime-logging-replay"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.replay_bucket_s3_access.arn,
  ]
}

resource "aws_lambda_function" "fraud_realtime_logging_replay_lambda" {
  function_name = "${var.environment}-fraud-realtime-logging-replay-lambda"
  role          = module.fraud_realtime_logging_replay_role.arn
  handler       = "uk.gov.di.authentication.audit.lambda.CounterFraudAuditReplayLambda::handleRequest"
  timeout       = 900
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
      AUDIT_HMAC_SECRET = random_password.hmac_key.result
    }
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  runtime = "java11"

  tags = local.default_tags
}

resource "aws_lambda_permission" "s3_can_execute_subscriber_fraud_realtime_logging_replay_lambda" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fraud_realtime_logging_replay_lambda.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.fraud_replay_bucket.arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.fraud_replay_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.fraud_realtime_logging_replay_lambda.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.s3_can_execute_subscriber_fraud_realtime_logging_replay_lambda]
}

resource "aws_cloudwatch_log_group" "fraud_realtime_logging_replay_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.fraud_realtime_logging_replay_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = local.cloudwatch_key_arn
  retention_in_days = 1 # We shouldn't hold onto this for long

  depends_on = [
    aws_lambda_function.fraud_realtime_logging_replay_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "fraud_realtime_logging_replay_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.fraud_realtime_logging_replay_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.fraud_realtime_logging_replay_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
