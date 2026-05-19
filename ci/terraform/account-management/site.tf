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
    elasticache = var.aws_endpoint
    kms         = var.aws_endpoint
    ssm         = var.aws_endpoint
    sts         = var.aws_endpoint
    iam         = var.aws_endpoint
    s3          = var.aws_endpoint
  }

  default_tags {
    tags = {
      Environment = var.environment
      Owner       = "di-authentication@digital.cabinet-office.gov.uk"
      Product     = "GOV.UK Sign In"
      System      = "Authentication"
      Service     = "account-management"

      application = "account-management-api"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_availability_zones" "available" {}
