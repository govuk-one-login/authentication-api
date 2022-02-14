module "account_management_sqs_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-sqs"
  vpc_arn     = local.vpc_arn
}

resource "aws_sqs_queue" "email_queue" {
  name                      = "${var.environment}-account-management-notification-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.email_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  tags = local.default_tags
}


resource "aws_sqs_queue" "email_dead_letter_queue" {
  name = "${var.environment}-account-management-dlq"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 3600 * 6

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
      identifiers = [module.account_management_api_remove_account_role.arn, module.account_management_api_update_email_role.arn, module.account_management_api_update_password_role.arn, module.account_management_api_update_phone_number_role.arn, module.account_management_api_send_notification_role.arn]
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
      identifiers = [module.account_management_sqs_role.arn]
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
    time_sleep.wait_60_seconds,
    module.account_management_sqs_role,
    module.account_management_api_remove_account_role,
    module.account_management_api_update_email_role,
    module.account_management_api_update_password_role,
    module.account_management_api_update_phone_number_role,
    module.account_management_api_send_notification_role,
  ]
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
    time_sleep.wait_60_seconds,
    module.account_management_sqs_role,
    module.account_management_api_remove_account_role,
    module.account_management_api_update_email_role,
    module.account_management_api_update_password_role,
    module.account_management_api_update_phone_number_role,
    module.account_management_api_send_notification_role,
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

resource "aws_sqs_queue_policy" "email_queue_policy" {
  depends_on = [
    time_sleep.wait_60_seconds,
    data.aws_iam_policy_document.email_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.email_queue.id
  policy    = data.aws_iam_policy_document.email_queue_policy_document.json
}

resource "aws_lambda_event_source_mapping" "lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.email_queue.arn
  function_name    = aws_lambda_function.email_sqs_lambda.arn

  depends_on = [
    aws_sqs_queue.email_queue,
    aws_sqs_queue_policy.email_queue_policy,
    aws_lambda_function.email_sqs_lambda,
    module.account_management_sqs_role
  ]
}

resource "aws_lambda_function" "email_sqs_lambda" {
  function_name = "${var.environment}-account-management-sqs-lambda"
  role          = module.account_management_sqs_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.NotificationHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.account_management_api_release_zip.key
  s3_object_version = aws_s3_bucket_object.account_management_api_release_zip.version_id

  vpc_config {
    security_group_ids = [local.allow_egress_security_group_id]
    subnet_ids         = local.private_subnet_ids
  }
  environment {
    variables = merge(var.notify_template_map, {
      FRONTEND_BASE_URL           = module.dns.frontend_url
      CUSTOMER_SUPPORT_LINK_ROUTE = var.customer_support_link_route
      NOTIFY_API_KEY              = var.notify_api_key
      NOTIFY_URL                  = var.notify_url
    })
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags

  depends_on = [
    module.account_management_sqs_role,
  ]
}

resource "aws_cloudwatch_log_group" "sqs_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.email_sqs_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.email_sqs_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "sqs_lambda_log_subscription" {
  count = var.logging_endpoint_enabled ? 1 : 0

  name            = "${aws_lambda_function.email_sqs_lambda.function_name}-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.sqs_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_lambda_alias" "sqs_lambda_active" {
  name             = "${aws_lambda_function.email_sqs_lambda.function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.email_sqs_lambda.arn
  function_version = aws_lambda_function.email_sqs_lambda.version
}
