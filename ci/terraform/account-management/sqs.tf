resource "aws_iam_role" "account_management_sqs_iam_role" {
  name = "${var.environment}-account-management-notification-sqs-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json

  tags = local.default_tags
}

resource "aws_iam_role_policy_attachment" "emaiL_lambda_logging_policy" {
  role       = aws_iam_role.account_management_sqs_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn

  depends_on = [
    aws_iam_role.account_management_sqs_iam_role,
    aws_iam_policy.endpoint_logging_policy,
  ]
}

resource "aws_iam_role_policy_attachment" "email_lambda_networking_policy" {
  role       = aws_iam_role.account_management_sqs_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn

  depends_on = [
    aws_iam_role.account_management_sqs_iam_role,
    aws_iam_policy.endpoint_networking_policy,
  ]
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

  message_retention_seconds = 3600

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
      identifiers = [aws_iam_role.dynamo_sqs_lambda_iam_role.arn]
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
      identifiers = [aws_iam_role.account_management_sqs_iam_role.arn]
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
    aws_iam_role.account_management_sqs_iam_role,
    aws_iam_role.dynamo_sqs_lambda_iam_role,
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
    aws_iam_role.account_management_sqs_iam_role,
    aws_iam_role.dynamo_sqs_lambda_iam_role,
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
    aws_iam_role.lambda_iam_role,
  ]
}

resource "aws_lambda_function" "email_sqs_lambda" {
  filename      = var.lambda_zip_file
  function_name = "${var.environment}-account-management-sqs-lambda"
  role          = aws_iam_role.account_management_sqs_iam_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.NotificationHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [aws_vpc.account_management_vpc.default_security_group_id]
    subnet_ids         = aws_subnet.account_management_subnets.*.id
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
    aws_iam_role.lambda_iam_role,
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
