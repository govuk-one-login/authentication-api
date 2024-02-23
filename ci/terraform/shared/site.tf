terraform {
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
    application = "shared"
  }

  request_tracing_allowed       = contains(["build", "sandpit"], var.environment)
  deploy_bulk_email_users_count = 0
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {}
