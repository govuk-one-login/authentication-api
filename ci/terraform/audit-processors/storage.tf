module "audit_storage_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "audit-storage"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.read_from_queue_policy.arn,
    aws_iam_policy.audit_payload_kms_verification.arn
  ], var.use_localstack ? [] : [aws_iam_policy.audit_storage_s3_access[0].arn])
}

resource "aws_iam_policy" "audit_payload_kms_verification" {
  name        = "payload-kms-verification"
  path        = "/${var.environment}/audit-storage/"
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

resource "aws_lambda_function" "audit_processor_lambda" {
  filename      = var.lambda_zip_file
  function_name = "${var.environment}-audit-storage-lambda"
  role          = module.audit_storage_lambda_role.arn
  handler       = "uk.gov.di.authentication.audit.lambda.StorageSQSAuditHandler::handleRequest"
  timeout       = 30
  memory_size   = 4096
  publish       = true

  tracing_config {
    mode = "Active"
  }

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [local.authentication_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = {
      AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
      LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
      TOKEN_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name,
      AUDIT_STORAGE_S3_BUCKET = var.use_localstack ? null : aws_s3_bucket.audit_storage_bucket[0].bucket
    }
  }

  runtime = "java11"

  tags = local.default_tags
}

resource "aws_sqs_queue_policy" "storage_batch_subscription" {
  queue_url = aws_sqs_queue.storage_batch.id
  policy    = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "sns.amazonaws.com"
      },
      "Action": [
        "sqs:SendMessage"
      ],
      "Resource": [
        "${aws_sqs_queue.storage_batch.arn}"
      ],
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${data.aws_sns_topic.event_stream.arn}"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_policy" "read_from_queue_policy" {
  name        = "${var.environment}-audit-processor-storage-sqs"
  path        = "/"
  description = "IAM policy for a lambda reading from SQS"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:DeleteMessage",
        "sqs:ReceiveMessage",
        "sqs:GetQueueAttributes"
      ]

      Resource = [
        aws_sqs_queue.storage_batch.arn,
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "read_from_queue_attachment" {
  count = var.use_localstack ? 0 : 1

  role       = local.lambda_iam_role_name
  policy_arn = aws_iam_policy.read_from_queue_policy.arn
}

resource "aws_sqs_queue" "storage_batch" {
  name                      = "${var.environment}-audit-storage-batch-queue"
  message_retention_seconds = 1209600

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.storage_batch_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  tags = local.default_tags
}

resource "aws_sqs_queue" "storage_batch_dead_letter_queue" {
  name = "${var.environment}-audit-storage-batch-dead-letter-queue"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 604800

  tags = local.default_tags
}

resource "aws_sns_topic_subscription" "event_stream_subscription" {
  topic_arn = data.aws_sns_topic.event_stream.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.storage_batch.arn
}

resource "aws_lambda_event_source_mapping" "audit_storage_batch_queue_subscription" {
  event_source_arn = aws_sqs_queue.storage_batch.arn
  function_name    = aws_lambda_function.audit_processor_lambda.arn
}

resource "aws_lambda_permission" "sqs_can_execute_subscriber_lambda" {
  statement_id  = "AllowExecutionFromSQS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit_processor_lambda.function_name
  principal     = "sqs.amazonaws.com"
  source_arn    = aws_sqs_queue.storage_batch.arn
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.audit_processor_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = local.cloudwatch_key_arn
  retention_in_days = local.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.audit_processor_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${aws_lambda_function.audit_processor_lambda.function_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "active_processor" {
  name             = "${aws_lambda_function.audit_processor_lambda.function_name}-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.audit_processor_lambda.arn
  function_version = aws_lambda_function.audit_processor_lambda.version
}

resource "aws_s3_bucket" "audit_storage_bucket" {
  count  = var.use_localstack ? 0 : 1
  bucket = "${var.environment}-audit-storage"

  acl = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "default-intelligent-tiering"
    enabled = true

    transition {
      days          = 1
      storage_class = "INTELLIGENT_TIERING"
    }
  }

  tags = local.default_tags
}

resource "aws_s3_bucket_public_access_block" "audit_storage_bucket_access" {
  count                   = var.use_localstack ? 0 : 1
  bucket                  = aws_s3_bucket.audit_storage_bucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "audit_storage_s3_access" {
  count       = var.use_localstack ? 0 : 1
  name        = "lambda-s3-access"
  path        = "/${var.environment}/audit-storage/"
  description = "IAM policy for managing s3 access from audit-storage lambda"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
      ]

      Resource = [
        aws_s3_bucket.audit_storage_bucket[0].arn,
        "${aws_s3_bucket.audit_storage_bucket[0].arn}/*"
      ]
    }]
  })
}
