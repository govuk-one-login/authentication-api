module "primary_environment" {
  source = "../modules/is-this-the-primary-environment"

  environment = var.environment
}

data "aws_iam_policy_document" "api_gateway_can_assume_policy" {
  count   = module.primary_environment.is_primary_environment ? 1 : 0
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "apigateway.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

locals {
  api_gateway_logging_role_name = "${var.aws_region}-api-gateway-logging-role"
}

// If this is the primary environment in this account/region, create the role
resource "aws_iam_role" "api_gateway_logging_role" {
  count              = module.primary_environment.is_primary_environment ? 1 : 0
  name               = local.api_gateway_logging_role_name
  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy[count.index].json
}


data "aws_iam_policy_document" "api_gateway_logging_policy" {
  count   = module.primary_environment.is_primary_environment ? 1 : 0
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

resource "aws_iam_role_policy" "api_gateway_can_log" {
  count  = module.primary_environment.is_primary_environment ? 1 : 0
  name   = "${var.aws_region}-api-gateway-allow-logging"
  role   = aws_iam_role.api_gateway_logging_role[count.index].id
  policy = data.aws_iam_policy_document.api_gateway_logging_policy[count.index].json
}

resource "aws_api_gateway_account" "api_gateway_region_settings" {
  count               = module.primary_environment.is_primary_environment ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_role[count.index].arn
}
