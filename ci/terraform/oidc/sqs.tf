resource "aws_iam_role" "email_lambda_iam_role" {
  name = "${var.environment}-email-notification-sqs-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json

  tags = local.default_tags
}

resource "aws_iam_role_policy_attachment" "emaiL_lambda_logging_policy" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn

  depends_on = [
    aws_iam_role.email_lambda_iam_role,
    aws_iam_policy.endpoint_logging_policy,
  ]
}

resource "aws_iam_role_policy_attachment" "email_lambda_networking_policy" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn

  depends_on = [
    aws_iam_role.email_lambda_iam_role,
    aws_iam_policy.endpoint_networking_policy,
  ]
}

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
      identifiers = [aws_iam_role.sqs_lambda_iam_role.arn, aws_iam_role.dynamo_sqs_lambda_iam_role.arn]
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
      identifiers = [aws_iam_role.email_lambda_iam_role.arn]
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
    aws_iam_role.email_lambda_iam_role,
    aws_iam_role.sqs_lambda_iam_role,
    aws_iam_role.dynamo_sqs_lambda_iam_role,
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
    aws_lambda_function.email_sqs_lambda,
    aws_iam_role.lambda_iam_role,
  ]
}

resource "aws_lambda_function" "email_sqs_lambda" {
  filename      = var.frontend_api_lambda_zip_file
  function_name = "${var.environment}-email-notification-sqs-lambda"
  role          = aws_iam_role.email_lambda_iam_role.arn
  handler       = "uk.gov.di.authentication.frontendapi.lambda.NotificationHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  source_code_hash = filebase64sha256(var.frontend_api_lambda_zip_file)
  vpc_config {
    security_group_ids = [aws_vpc.authentication.default_security_group_id]
    subnet_ids         = aws_subnet.authentication.*.id
  }
  environment {
    variables = {
      VERIFY_EMAIL_TEMPLATE_ID                = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
      VERIFY_PHONE_NUMBER_TEMPLATE_ID         = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
      MFA_SMS_TEMPLATE_ID                     = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
      RESET_PASSWORD_TEMPLATE_ID              = "0aaf3ae8-1825-4528-af95-3093eb13fda0"
      PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID = "052d4e96-e6ca-4da2-b657-5649f28bd6c0"
      FRONTEND_BASE_URL                       = local.frontend_base_url
      RESET_PASSWORD_ROUTE                    = var.reset_password_route
      NOTIFY_API_KEY                          = var.notify_api_key
      NOTIFY_URL                              = var.notify_url
    }
  }

  tags = local.default_tags

  depends_on = [
    aws_iam_role.lambda_iam_role,
  ]
}
