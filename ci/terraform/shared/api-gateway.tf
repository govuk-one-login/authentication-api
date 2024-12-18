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

resource "aws_api_gateway_account" "api_gateway_region_settings" {
  count               = module.primary_environment.is_primary_environment ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_role[count.index].arn
}

output "api_gateway_logging_role_name" {
  value       = local.api_gateway_logging_role_name
  description = "Name of the IAM role used by API Gateway to log requests"
}
