terraform {
  backend "s3" {
  }
}
provider "aws" {
  region = var.aws_region
  assume_role {
    role_arn = var.deployer_role_arn
  }
  insecure                    = false
  s3_use_path_style           = false
  skip_credentials_validation = false
  skip_metadata_api_check     = false
  skip_requesting_account_id  = false
}

locals {
  // Using a local rather than the default_tags option on the AWS provider, as the latter has known issues which produce errors on apply.
  default_tags = {
    environment = var.environment
    application = "interventions-api-stub"
  }

  request_tracing_allowed = contains(["build", "sandpit"], var.environment)

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
