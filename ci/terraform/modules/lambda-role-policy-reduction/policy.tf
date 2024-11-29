data "aws_iam_policy_document" "logging_policy_document" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

data "aws_iam_policy_document" "endpoint_xray_policy" {
  statement {
    effect = "Allow"
    actions = [
      "xray:*"
    ]

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "networking_policy_document" {
  count = var.vpc_arn == "" ? 0 : 1
  statement {
    effect = "Allow"

    actions = [
      "ec2:DescribeNetworkInterfaces",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface"
    ]
    resources = [
      "*"
    ]
    condition {
      test     = "ArnLikeIfExists"
      variable = "ec2:Vpc"
      values   = [var.vpc_arn]
    }
  }
}

locals {
  policy_documents_to_attach = merge({
    base = concat([
      data.aws_iam_policy_document.logging_policy_document.json,
      data.aws_iam_policy_document.endpoint_xray_policy.json,
      ],
    var.vpc_arn == "" ? [] : [data.aws_iam_policy_document.networking_policy_document[0].json]),
  }, var.policy_documents_to_attach)
}

data "aws_iam_policy_document" "iam-policy-document" {
  for_each                = local.policy_documents_to_attach
  source_policy_documents = each.value
}

resource "aws_iam_policy" "iam-policy" {
  for_each = local.policy_documents_to_attach

  name_prefix = "${var.role_name}-${each.key}-policy"
  path        = "/${var.environment}/${var.role_name}/"
  description = "Combined IAM policy ${each.key} for ${var.role_name}"

  policy = data.aws_iam_policy_document.iam-policy-document[each.key].json
}
