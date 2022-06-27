terraform {
  required_version = ">= 1.0.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 3.63.0"
    }
  }

  backend "s3" {
  }
}

provider "aws" {
  region = var.aws_region

  assume_role {
    role_arn = var.deployer_role_arn
  }

  insecure = var.use_localstack

  s3_force_path_style         = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  endpoints {
    iam    = var.aws_endpoint
    lambda = var.aws_endpoint
    sqs    = var.aws_endpoint
    sns    = var.aws_endpoint
  }
}

locals {
  // Using a local rather than the default_tags option on the AWS provider, as the latter has known issues which produce errors on apply.
  default_tags = {
    environment = var.environment
    application = "audit-processors"
  }
}


data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
