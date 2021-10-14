resource "aws_iam_role" "lambda_role" {
  name = "${var.environment}-${var.role_name}-lambda-role"

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
}
