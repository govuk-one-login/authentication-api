terraform {
  backend "s3" {
  }
}

provider "aws" {
  region = var.aws_region

  assume_role {
    role_arn = var.deployer_role_arn
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
    sqs         = var.aws_endpoint
    sts         = var.aws_endpoint
    elasticache = var.aws_endpoint
    kms         = var.aws_endpoint
    dynamodb    = var.aws_dynamodb_endpoint
    sns         = var.aws_endpoint
  }
}

locals {
  // Using a local rather than the default_tags option on the AWS provider, as the latter has known issues which produce errors on apply.
  default_tags = var.use_localstack ? null : {
    environment = var.environment
    application = "oidc-api"
  }

  request_tracing_allowed              = contains(["build", "sandpit"], var.environment)
  deploy_account_interventions_count   = 1
  deploy_ticf_cri_count                = contains(["sandpit", "authdev1", "authdev2"], var.environment) ? 1 : 0
  deploy_reauth_user_count             = contains(["build", "sandpit", "authdev1", "authdev2", "staging", "integration"], var.environment) ? 1 : 0
  deploy_check_email_fraud_block_count = contains(["build", "sandpit", "authdev1", "authdev2", "staging"], var.environment) ? 1 : 0

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
