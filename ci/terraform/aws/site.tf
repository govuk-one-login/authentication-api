terraform {
  required_version = "> 0.14"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "3.37.0"
    }
  }

  backend "s3" {
    bucket  = "digital-identity-dev-tfstate"
    key     = "spike-terraform.tfstate"
    encrypt = true
    region  = "eu-west-2"
  }
}

provider "aws" {
  region  = "eu-west-2"

  assume_role {
    role_arn = var.deployer-role-arn
  }
}