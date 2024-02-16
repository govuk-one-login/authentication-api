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
    application = "account-management-api"
  }

  request_tracing_allowed = contains(["build", "sandpit"], var.environment)

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
