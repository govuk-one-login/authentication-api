data "aws_dynamodb_table" "international_sms_send_count" {
  name = "${var.environment}-international-sms-send-count"
}

data "aws_iam_policy_document" "international_send_count_delete_dynamo_access" {
  statement {
    sid    = "AllowScanAndDeleteInternationalSendCount"
    effect = "Allow"

    actions = [
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
    ]

    resources = [
      data.aws_dynamodb_table.international_sms_send_count.arn,
    ]
  }
  statement {
    sid    = "AllowAccessToKms"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [data.terraform_remote_state.shared.outputs.international_sms_send_count_encryption_key_arn]
  }
}

resource "aws_iam_policy" "international_send_count_delete_dynamo_access" {
  name_prefix = "intl-send-count-delete-dynamo-access-policy"
  description = "IAM policy for managing permissions for the international send count delete lambda"

  policy = data.aws_iam_policy_document.international_send_count_delete_dynamo_access.json
}

module "international_send_count_delete_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "international-send-count-delete-lambda-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.international_send_count_delete_dynamo_access.arn,
  ]
}

resource "aws_lambda_function" "international_send_count_delete_lambda" {
  function_name                  = "${var.environment}-international-send-count-delete-lambda"
  role                           = module.international_send_count_delete_lambda_role.arn
  handler                        = "uk.gov.di.authentication.utils.lambda.InternationalSendCountDeleteHandler::handleRequest"
  timeout                        = 900
  memory_size                    = 4096
  reserved_concurrent_executions = 1
  runtime                        = "java17"
  publish                        = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  vpc_config {
    security_group_ids = [local.allow_aws_service_access_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids
  }

  environment {
    variables = merge({
      ENVIRONMENT = var.environment
    })
  }
}

resource "aws_cloudwatch_log_group" "international_send_count_delete_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.international_send_count_delete_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_subscription_filter" "international_send_count_delete_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.international_send_count_delete_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.international_send_count_delete_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
