module "experian_phone_checker_sqs_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "experian-phone-checker-shared-sqs"
  vpc_arn     = local.authentication_vpc_arn
}

resource "aws_sqs_queue" "experian_phone_checker_queue" {
  name                       = "${var.environment}-experian-phone-checker-queue"
  max_message_size           = 2048
  message_retention_seconds  = 60
  visibility_timeout_seconds = 180

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.experian_phone_checker_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  tags = local.default_tags
}


resource "aws_sqs_queue" "experian_phone_checker_dead_letter_queue" {
  name          = "${var.environment}-experian_phone_checker-dlq"
  delay_seconds = 300

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 3600 * 6

  tags = local.default_tags
}

data "aws_iam_policy_document" "experian_phone_checker_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.frontend_api_verify_mfa_code_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.experian_phone_checker_queue.arn
    ]
  }

  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.experian_phone_checker_sqs_role.arn]
    }

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.experian_phone_checker_queue.arn
    ]
  }

  depends_on = [
    module.experian_phone_checker_sqs_role,
    module.frontend_api_verify_mfa_code_role,
  ]
}

data "aws_iam_policy_document" "experian_phone_checker_dl_queue_policy_document" {
  statement {
    sid    = "SendAndReceive"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root", module.experian_phone_checker_sqs_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [aws_sqs_queue.experian_phone_checker_dead_letter_queue.arn]
  }

  depends_on = [
    module.experian_phone_checker_sqs_role,
  ]
}

resource "aws_sqs_queue_policy" "experian_phone_checker_dl_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.experian_phone_checker_dl_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.experian_phone_checker_dead_letter_queue.id
  policy    = data.aws_iam_policy_document.experian_phone_checker_dl_queue_policy_document.json
}

resource "aws_sqs_queue_policy" "experian_phone_checker_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.email_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.experian_phone_checker_queue.id
  policy    = data.aws_iam_policy_document.experian_phone_checker_queue_policy_document.json
}

resource "aws_lambda_function" "experian_phone_checker_sqs_lambda" {
  function_name = "${var.environment}-experian-phone-checker-sqs-lambda"
  role          = module.experian_phone_checker_sqs_role.arn
  handler       = "uk.gov.di.authentication.contraindicators.experianphonecheck.lambda.ExperianPhoneCheckSQSHandler::handleRequest"
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
    subnet_ids         = local.authentication_private_subnet_ids
  }
  environment {
    variables = merge(var.notify_template_map, {
      JAVA_TOOL_OPTIONS = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
    })
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags

  depends_on = [
    module.experian_phone_checker_sqs_role,
  ]
}

resource "aws_lambda_alias" "experian_sqs_lambda_active" {
  name             = "${aws_lambda_function.experian_phone_checker_sqs_lambda.function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.experian_phone_checker_sqs_lambda.arn
  function_version = aws_lambda_function.experian_phone_checker_sqs_lambda.version
}

resource "aws_lambda_event_source_mapping" "experian_lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.experian_phone_checker_queue.arn
  function_name    = aws_lambda_function.experian_phone_checker_sqs_lambda.arn

  depends_on = [
    aws_sqs_queue.experian_phone_checker_queue,
    aws_sqs_queue_policy.experian_phone_checker_queue_policy,
    aws_lambda_function.experian_phone_checker_sqs_lambda,
    module.experian_phone_checker_sqs_role
  ]
}

resource "aws_lambda_event_source_mapping" "experian_dlq_lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.experian_phone_checker_dead_letter_queue.arn
  function_name    = aws_lambda_function.experian_phone_checker_sqs_lambda.arn

  depends_on = [
    aws_sqs_queue.experian_phone_checker_dead_letter_queue,
    aws_sqs_queue_policy.experian_phone_checker_dl_queue_policy,
    aws_lambda_function.experian_phone_checker_sqs_lambda,
    module.experian_phone_checker_sqs_role
  ]
}

resource "aws_cloudwatch_log_group" "experian_sqs_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.experian_phone_checker_sqs_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.experian_phone_checker_sqs_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "experian_sqs_lambda_log_subscription" {
  count = length(var.logging_endpoint_arns)

  name            = "${aws_lambda_function.experian_phone_checker_sqs_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.sqs_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}