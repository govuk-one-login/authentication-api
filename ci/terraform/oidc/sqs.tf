resource "aws_sqs_queue" "email_queue" {
  name                      = "${var.environment}-email-notification-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

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
      identifiers = [local.sqs_lambda_iam_role_arn, local.dynamo_sqs_lambda_iam_role_arn]
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
      identifiers = [local.email_lambda_iam_role_arn]
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
  filename      = var.frontend_api_lambda_zip_file
  function_name = "${var.environment}-email-notification-sqs-lambda"
  role          = local.email_lambda_iam_role_arn
  handler       = "uk.gov.di.authentication.frontendapi.lambda.NotificationHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  source_code_hash = filebase64sha256(var.frontend_api_lambda_zip_file)
  vpc_config {
    security_group_ids = [local.authentication_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = merge(var.notify_template_map, {
      FRONTEND_BASE_URL    = local.frontend_base_url
      RESET_PASSWORD_ROUTE = var.reset_password_route
      NOTIFY_API_KEY       = var.notify_api_key
      NOTIFY_URL           = var.notify_url
    })
  }

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
  count           = var.logging_endpoint_enabled ? 1 : 0
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
