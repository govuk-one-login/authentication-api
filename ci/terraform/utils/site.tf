terraform {
  backend "s3" {
  }
}

provider "aws" {
  region = var.aws_region

  dynamic "assume_role" {
    for_each = var.deployer_role_arn != null ? [var.deployer_role_arn] : []
    content {
      role_arn = assume_role.value
    }
  }

  endpoints {
    apigateway = var.aws_endpoint
    iam        = var.aws_endpoint
    lambda     = var.aws_endpoint
    s3         = var.aws_endpoint
    dynamodb   = var.aws_dynamodb_endpoint
  }

  default_tags {
    tags = {
      Environment = var.environment
      Owner       = "di-authentication@digital.cabinet-office.gov.uk"
      Product     = "GOV.UK Sign In"
      System      = "Authentication"
      Service     = "utils"

      application = "utils"
    }
  }
}

locals {
  request_tracing_allowed                     = contains(["build", "sandpit"], var.environment)
  deploy_bulk_email_users_count               = 0
  bulk_user_email_audience_loader_lambda_name = "${var.environment}-bulk-user-email-audience-loader-lambda"
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {}
