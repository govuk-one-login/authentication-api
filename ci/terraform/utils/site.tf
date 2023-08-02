terraform {
  required_version = ">= 1.0.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 4.19.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.7.1"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.1.0"
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

  insecure = false


  s3_use_path_style           = false
  skip_credentials_validation = false
  skip_metadata_api_check     = false
  skip_requesting_account_id  = false

  endpoints {
    apigateway = var.aws_endpoint
    iam        = var.aws_endpoint
    lambda     = var.aws_endpoint
    s3         = var.aws_endpoint
    dynamodb   = var.aws_dynamodb_endpoint
  }
}

locals {
  // Using a local rather than the default_tags option on the AWS provider, as the latter has known issues which produce errors on apply.
  default_tags = {
    environment = var.environment
    application = "utils"
  }

  request_tracing_allowed = contains(["build", "sandpit"], var.environment)
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {}
