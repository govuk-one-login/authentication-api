terraform {
  backend "s3" {
  }
}

locals {
  shared_default_tags = {
    Environment = var.environment
    Owner       = "di-authentication@digital.cabinet-office.gov.uk"
    Product     = "GOV.UK Sign In"
    System      = "Authentication"
    Service     = "shared"

    application = "shared"
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
    apigateway  = var.aws_endpoint
    ecr         = var.aws_endpoint
    iam         = var.aws_endpoint
    lambda      = var.aws_endpoint
    s3          = var.aws_endpoint
    ec2         = var.aws_endpoint
    sqs         = var.aws_endpoint
    sts         = var.aws_endpoint
    elasticache = var.aws_endpoint
    kms         = var.aws_endpoint
    ssm         = var.aws_endpoint
    dynamodb    = var.aws_dynamodb_endpoint
    sns         = var.aws_endpoint
  }

  default_tags {
    tags = local.shared_default_tags
  }
}


provider "aws" {
  alias = "cloudfront"

  region = "us-east-1"

  dynamic "assume_role" {
    for_each = var.deployer_role_arn != null ? [var.deployer_role_arn] : []
    content {
      role_arn = assume_role.value
    }
  }

  default_tags {
    tags = local.shared_default_tags
  }
}

locals {
  deploy_bulk_email_users_count = 0
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {}
