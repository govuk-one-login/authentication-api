resource "aws_sns_topic" "cloudfront_alerts" {
  provider = aws.cloudfront
  name     = "${var.environment}-oidc-cloudfront-alerts"
  # checkov:skip=CKV_AWS_26:No encryption needed on alerts topic
}

data "aws_iam_policy_document" "cloudfront_alerts" {
  provider = aws.cloudfront
  version  = "2012-10-17"

  statement {
    actions = [
      "sns:Publish"
    ]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      values   = [data.aws_caller_identity.current.account_id]
      variable = "aws:SourceAccount"
    }

    resources = [
      aws_sns_topic.cloudfront_alerts.arn,
    ]
  }
}

resource "aws_sns_topic_policy" "cloudfront_alerts" {
  provider = aws.cloudfront
  arn      = aws_sns_topic.cloudfront_alerts.arn

  policy = data.aws_iam_policy_document.cloudfront_alerts.json
}
