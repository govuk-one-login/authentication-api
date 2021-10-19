resource "aws_iam_role" "lambda_role" {
  name_prefix        = "execution-role"
  path               = "/${var.environment}/${var.role_name}/"
  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_role.json

  tags = var.default_tags
}

data "aws_iam_policy_document" "lambda_can_assume_role" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "lambda.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role_policy_attachment" "provided_policies" {
  count      = length(var.policies_to_attach)
  role       = aws_iam_role.lambda_role.name
  policy_arn = var.policies_to_attach[count.index]

  depends_on = [
    aws_iam_role.lambda_role
  ]
}

resource "aws_iam_policy" "logging_policy" {
  name_prefix = "logging"
  path        = "/${var.environment}/${var.role_name}/"
  description = "IAM policy for logging from a lambda"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]

      Resource = [
        "arn:aws:logs:*:*:*",
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.logging_policy.arn

  depends_on = [
    aws_iam_role.lambda_role,
    aws_iam_policy.logging_policy
  ]
}

resource "aws_iam_policy" "networking_policy" {
  name_prefix = "networking"
  path        = "/${var.environment}/${var.role_name}/"
  description = "IAM policy for managing VPC connection for a lambda"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:DescribeNetworkInterfaces",
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface"
      ]
      Resource = ["*"]
      Condition = {
        ArnLikeIfExists = {
          "ec2:Vpc" = [var.vpc_arn]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "networking_policy" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.networking_policy.arn

  depends_on = [
    aws_iam_role.lambda_role,
    aws_iam_policy.networking_policy
  ]
}