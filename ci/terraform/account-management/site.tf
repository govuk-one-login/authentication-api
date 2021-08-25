terraform {
  required_version = ">= 1.0.4"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = ">= 3.54.0"
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
}

locals {
  // Using a local rather than the default_tags option on the AWS provider, as the latter has known issues which produce errors on apply.
  default_tags = {
    environment = var.environment
    application = "account-management-api"
  }
}