module "oidc_email_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-email"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.s3_smoketest_policy.arn
  ]
}

resource "aws_sqs_queue" "email_queue" {
  name                       = "${var.environment}-email-notification-queue"
  max_message_size           = 2048
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 180
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.email_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  tags = local.default_tags
}

resource "aws_sqs_queue" "email_dead_letter_queue" {
  name = "${var.environment}-email-notification-dlq"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 60 * 60 * 24 * 5

  tags = local.default_tags
}

resource "time_sleep" "wait_60_seconds" {
  depends_on = [aws_sqs_queue.email_queue]
  count      = var.use_localstack ? 0 : 1

  create_duration = "60s"
}

data "aws_iam_policy_document" "email_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.frontend_api_send_notification_role.arn, module.frontend_api_mfa_role.arn, module.frontend_api_reset_password_request_role.arn, module.frontend_api_reset_password_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.email_queue.arn
    ]
  }

  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.oidc_email_role.arn]
    }

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.email_queue.arn
    ]
  }

  depends_on = [
    time_sleep.wait_60_seconds
  ]
}

resource "aws_sqs_queue_policy" "email_queue_policy" {
  depends_on = [
    time_sleep.wait_60_seconds,
    data.aws_iam_policy_document.email_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.email_queue.id
  policy    = data.aws_iam_policy_document.email_queue_policy_document.json
}

data "aws_iam_policy_document" "email_dlq_queue_policy_document" {
  statement {
    sid    = "SendAndReceive"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [aws_sqs_queue.email_dead_letter_queue.arn]
  }

  depends_on = [
    time_sleep.wait_60_seconds
  ]
}

resource "aws_sqs_queue_policy" "email_dlq_queue_policy" {
  depends_on = [
    time_sleep.wait_60_seconds,
    data.aws_iam_policy_document.email_dlq_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.email_dead_letter_queue.id
  policy    = data.aws_iam_policy_document.email_dlq_queue_policy_document.json
}

resource "aws_lambda_event_source_mapping" "lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.email_queue.arn
  function_name    = aws_lambda_function.email_sqs_lambda.arn

  depends_on = [
    aws_sqs_queue.email_queue,
    aws_sqs_queue_policy.email_queue_policy,
    aws_lambda_function.email_sqs_lambda
  ]
}

resource "aws_lambda_function" "email_sqs_lambda" {
  function_name = "${var.environment}-email-notification-sqs-lambda"
  role          = module.oidc_email_role.arn
  handler       = "uk.gov.di.authentication.frontendapi.lambda.NotificationHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java17"
  publish       = true

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_object.frontend_api_release_zip.key
  s3_object_version = aws_s3_object.frontend_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = merge(var.notify_template_map, {
      FRONTEND_BASE_URL            = "https://${local.frontend_fqdn}/"
      ACCOUNT_MANAGEMENT_URI       = "https://${local.account_management_fqdn}/"
      RESET_PASSWORD_ROUTE         = var.reset_password_route
      CONTACT_US_LINK_ROUTE        = var.contact_us_link_route
      GOV_UK_ACCOUNTS_URL          = var.gov_uk_accounts_url
      NOTIFY_API_KEY               = var.notify_api_key
      NOTIFY_URL                   = var.notify_url
      NOTIFY_TEST_DESTINATIONS     = var.notify_test_destinations
      NOTIFY_TEMPLATE_PER_LANGUAGE = var.notify_template_per_language
      SMOKETEST_SMS_BUCKET_NAME    = local.sms_bucket_name
      JAVA_TOOL_OPTIONS            = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
      ENVIRONMENT                  = var.environment
    })
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "sqs_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.email_sqs_lambda.function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.email_sqs_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "sqs_lambda_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.email_sqs_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.sqs_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_lambda_alias" "sqs_lambda_active" {
  name             = "${aws_lambda_function.email_sqs_lambda.function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.email_sqs_lambda.arn
  function_version = aws_lambda_function.email_sqs_lambda.version
}

### Smoketest codes S3

data "aws_s3_bucket" "smoketest_sms_bucket" {
  bucket = "${var.environment}-smoke-test-sms-codes"
}

resource "aws_iam_policy" "s3_smoketest_policy" {
  name_prefix = "s3-smoketest-access"
  path        = "/${var.environment}/"
  description = "IAM policy for managing S3 connection to the S3 Smoketest bucket"

  policy = data.aws_iam_policy_document.s3_smoketest_policy_document.json
}

data "aws_iam_policy_document" "s3_smoketest_policy_document" {
  statement {
    sid    = "AllowAccessToWriteToS3"
    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]
    resources = [
      data.aws_s3_bucket.smoketest_sms_bucket.arn,
      "${data.aws_s3_bucket.smoketest_sms_bucket.arn}/*",
    ]
  }
}
