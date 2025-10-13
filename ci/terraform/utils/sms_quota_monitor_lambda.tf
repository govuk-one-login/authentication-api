data "aws_iam_policy_document" "sms_quota_monitor_cloudwatch_access" {
  statement {
    sid    = "AllowAccessToCloudWatchMetrics"
    effect = "Allow"

    actions = [
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:PutMetricData",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "sms_quota_monitor_cloudwatch_access" {
  name_prefix = "sms-quota-monitor-cloudwatch-access-policy"
  description = "IAM policy for SMS quota monitor to access CloudWatch metrics"

  policy = data.aws_iam_policy_document.sms_quota_monitor_cloudwatch_access.json
}

module "sms_quota_monitor_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "sms-quota-monitor-lambda-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.sms_quota_monitor_cloudwatch_access.arn,
  ]
}

resource "aws_lambda_function" "sms_quota_monitor_lambda" {
  function_name                  = "${var.environment}-sms-quota-monitor-lambda"
  role                           = module.sms_quota_monitor_lambda_role.arn
  handler                        = "uk.gov.di.authentication.utils.lambda.SmsQuotaMonitorHandler::handleRequest"
  timeout                        = 300
  memory_size                    = 512
  reserved_concurrent_executions = 1
  runtime                        = "java17"
  publish                        = true

  kms_key_arn             = local.lambda_env_vars_encryption_kms_key_arn
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids
  }

  environment {
    variables = {
      ENVIRONMENT                       = var.environment
      DOMESTIC_SMS_QUOTA_THRESHOLD      = var.domestic_sms_quota_threshold
      INTERNATIONAL_SMS_QUOTA_THRESHOLD = var.international_sms_quota_threshold
      SMS_SENT_METRIC_PRODUCER          = data.terraform_remote_state.oidc.outputs.email_sqs_lambda_function_name
    }
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_cloudwatch_log_group" "sms_quota_monitor_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.sms_quota_monitor_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = 365
}

resource "aws_cloudwatch_log_subscription_filter" "sms_quota_monitor_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.sms_quota_monitor_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.sms_quota_monitor_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

variable "sms_quota_monitor_schedule_rate" {
  description = "Schedule rate for SMS quota monitor Lambda (optional)"
  type        = string
  default     = null
}

resource "aws_cloudwatch_event_rule" "sms_quota_monitor_schedule" {
  count               = var.sms_quota_monitor_schedule_rate != null ? 1 : 0
  name                = "${var.environment}-sms-quota-monitor-schedule"
  schedule_expression = var.sms_quota_monitor_schedule_rate
}

resource "aws_cloudwatch_event_target" "sms_quota_monitor_schedule_target" {
  count     = var.sms_quota_monitor_schedule_rate != null ? 1 : 0
  arn       = aws_lambda_function.sms_quota_monitor_lambda.arn
  rule      = aws_cloudwatch_event_rule.sms_quota_monitor_schedule[0].name
  target_id = aws_lambda_function.sms_quota_monitor_lambda.version
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_sms_quota_monitor_lambda" {
  count         = var.sms_quota_monitor_schedule_rate != null ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sms_quota_monitor_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sms_quota_monitor_schedule[0].arn
}
