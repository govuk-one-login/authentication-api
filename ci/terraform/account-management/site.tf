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
