resource "aws_iam_policy" "cloudwatch_metrics_putdata_policy" {
  name_prefix = "cloudwatch-put-metrics-policy-"
  path        = "/${var.environment}/frontend-shared/"
  description = "IAM policy enabling pushing metrics to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["cloudwatch:PutMetricData"]
      Resource = ["*"]
    }]
  })
}