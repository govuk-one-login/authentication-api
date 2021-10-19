data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket                      = var.shared_state_bucket
    key                         = "${var.environment}-shared-terraform.tfstate"
    role_arn                    = var.deployer_role_arn
    region                      = var.aws_region
    endpoint                    = var.use_localstack ? "http://localhost:45678" : null
    iam_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    sts_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    skip_credentials_validation = var.use_localstack
    skip_metadata_api_check     = var.use_localstack
    force_path_style            = var.use_localstack
  }
}

locals {
  authentication_security_group_id = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  authentication_subnet_ids        = data.terraform_remote_state.shared.outputs.authentication_subnet_ids
  lambda_iam_role_arn              = data.terraform_remote_state.shared.outputs.lambda_iam_role_arn
  lambda_iam_role_name             = data.terraform_remote_state.shared.outputs.lambda_iam_role_name
  audit_signing_key_alias_name     = data.terraform_remote_state.shared.outputs.audit_signing_key_alias_name
  audit_signing_key_arn            = data.terraform_remote_state.shared.outputs.audit_signing_key_arn
  logging_endpoint_enabled         = var.logging_endpoint_enabled
  logging_endpoint_arn             = var.logging_endpoint_arn
  cloudwatch_key_arn               = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention         = 5
  authentication_vpc_arn           = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
}

data "aws_sns_topic" "event_stream" {
  name = "${var.environment}-events"
}