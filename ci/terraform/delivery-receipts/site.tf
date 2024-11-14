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

  insecure = var.use_localstack

  s3_use_path_style           = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  endpoints {
    apigateway  = var.aws_endpoint
    ecr         = var.aws_endpoint
    iam         = var.aws_endpoint
    lambda      = var.aws_endpoint
    s3          = var.aws_endpoint
    ec2         = var.aws_endpoint
    sts         = var.aws_endpoint
    elasticache = var.aws_endpoint
  }

  default_tags {
    tags = {
      environment = var.environment
      application = "delivery-receipts-api"
    }
  }
}

locals {
  request_tracing_allowed       = contains(["build", "sandpit"], var.environment)
  deploy_bulk_email_users_count = 0

  access_logging_template = jsonencode({
    requestId            = "$context.requestId"
    ip                   = "$context.identity.sourceIp"
    userAgent            = "$context.identity.userAgent"
    requestTime          = "$context.requestTime"
    httpMethod           = "$context.httpMethod"
    resourcePath         = "$context.resourcePath"
    status               = "$context.status"
    protocol             = "$context.protocol"
    responseLength       = "$context.responseLength"
    integrationStatus    = "$context.integration.integrationStatus"
    integrationLatency   = "$context.integration.latency"
    integrationRequestId = "$context.integration.requestId"
  })
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
