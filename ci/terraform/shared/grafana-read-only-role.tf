data "aws_iam_policy_document" "tools_account_assume_role_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "arn:aws:iam::${var.tools_account_id}:root"
      ]
      type = "AWS"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "grafana_metrics_read_only_role" {
  count = contains(["integration", "production", "staging"], var.environment) ? 1 : 0
  name  = "grafana-metrics-read-only"

  assume_role_policy = data.aws_iam_policy_document.tools_account_assume_role_policy.json

  tags = local.default_tags
}

data "aws_iam_policy_document" "metrics_access_policy_document" {

  version = "2012-10-17"

  statement {
    sid    = "AllowReadingMetricsFromCloudWatch"
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarmsForMetric",
      "cloudwatch:DescribeAlarmHistory",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListMetrics",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:GetMetricData"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowReadingTagsInstancesRegionsFromEC2"
    effect = "Allow"
    actions = [
      "ec2:DescribeTags",
      "ec2:DescribeInstances",
      "ec2:DescribeRegions"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowReadingResourcesForTags"
    effect = "Allow"
    actions = [
      "tag:GetResources"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "metrics_access_policy" {
  count = contains(["integration", "production", "staging"], var.environment) ? 1 : 0

  name        = "grafana-metrics-read-only-policy"
  description = "IAM policy for read-only access to Cloudwatch metrics"

  policy = data.aws_iam_policy_document.metrics_access_policy_document.json
}

resource "aws_iam_role_policy_attachment" "metrics_access" {
  count      = contains(["integration", "production", "staging"], var.environment) ? 1 : 0
  role       = aws_iam_role.grafana_metrics_read_only_role[0].name
  policy_arn = aws_iam_policy.metrics_access_policy[0].arn
}
