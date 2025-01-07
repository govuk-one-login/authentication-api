resource "aws_sns_topic" "slack_events" {
  name                             = "${var.environment}-slack-events"
  lambda_failure_feedback_role_arn = aws_iam_role.sns_logging_iam_role.arn
}

output "slack_event_sns_topic_arn" {
  description = "The ARN of the SNS topic for Slack events"
  value       = aws_sns_topic.slack_events.arn
}

data "aws_iam_policy_document" "sns_topic_policy" {
  version = "2012-10-17"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.slack_events.arn,
    ]
  }
}

resource "aws_sns_topic_policy" "sns_alert_policy" {
  arn = aws_sns_topic.slack_events.arn

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

resource "aws_iam_role" "sns_logging_iam_role" {
  name = "${var.environment}-sns-slack-alert-role"

  assume_role_policy = data.aws_iam_policy_document.sns_can_assume_policy.json
}

data "aws_iam_policy_document" "sns_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "sns.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

data "aws_iam_policy_document" "sns_logging_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-sns-alert-logging"
  path        = "/"
  description = "IAM policy for logging for SNS alerts"

  policy = data.aws_iam_policy_document.sns_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.sns_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

resource "aws_cloudwatch_log_group" "sns_log_group" {
  name              = "/aws/lambda/${aws_sns_topic.slack_events.name}"
  kms_key_id        = aws_kms_key.cloudwatch_log_encryption.arn
  retention_in_days = 30

  depends_on = [
    aws_sns_topic.slack_events
  ]
}
moved {
  from = aws_cloudwatch_log_group.sns_log_group[0]
  to   = aws_cloudwatch_log_group.sns_log_group
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_sns_topic.slack_events.name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.sns_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
