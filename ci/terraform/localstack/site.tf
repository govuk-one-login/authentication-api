terraform {
  required_version = "> 0.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.37.0"
    }
  }
}

provider "aws" {
  alias                       = "localstack"
  access_key                  = "mock_access_key"
  region                      = "eu-west-2"
  s3_force_path_style         = false
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    apigateway = "http://localhost:45678"
    ecr        = "http://localhost:45678"
    iam        = "http://localhost:45678"
    lambda     = "http://localhost:45678"
    s3         = "http://localhost:45678"
    ec2        = "http://localhost:45678"
  }
}