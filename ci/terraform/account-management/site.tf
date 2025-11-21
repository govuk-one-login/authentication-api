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
    apigateway  = var.aws_endpoint
    ecr         = var.aws_endpoint
    iam         = var.aws_endpoint
    lambda      = var.aws_endpoint
    s3          = var.aws_endpoint
    ec2         = var.aws_endpoint
    sqs         = var.aws_endpoint
    sts         = var.aws_endpoint
    ssm         = var.aws_endpoint
    elasticache = var.aws_endpoint
    kms         = var.aws_endpoint
    dynamodb    = var.aws_dynamodb_endpoint
    sns         = var.aws_endpoint
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
locals {
  request_tracing_allowed = contains(["build"], var.environment)

  access_logging_template = jsonencode({
    requestId                    = "$context.requestId"
    ip                           = "$context.identity.sourceIp"
    userAgent                    = "$context.identity.userAgent"
    requestTime                  = "$context.requestTime"
    httpMethod                   = "$context.httpMethod"
    resourcePath                 = "$context.resourcePath"
    status                       = "$context.status"
    protocol                     = "$context.protocol"
    responseLength               = "$context.responseLength"
    integrationStatus            = "$context.integration.integrationStatus"
    integrationLatency           = "$context.integration.latency"
    integrationRequestId         = "$context.integration.requestId"
    authorizerError              = "$context.authorizer.error"
    authorizerIntegrationLatency = "$context.authorizer.integrationLatency"
    authorizerIntegrationStatus  = "$context.authorizer.integrationStatus"
    authorizerLatency            = "$context.authorizer.latency"
    authorizerRequestId          = "$context.authorizer.requestId"
    authorizerStatus             = "$context.authorizer.status"
  })
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_availability_zones" "available" {}
