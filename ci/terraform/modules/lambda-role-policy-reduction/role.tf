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
  for_each = aws_iam_policy.iam-policy

  role       = aws_iam_role.lambda_role.name
  policy_arn = each.value.arn

  depends_on = [
    aws_iam_role.lambda_role
  ]
}
