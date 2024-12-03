data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket      = var.common_state_bucket
    key         = "${var.environment}-shared-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region

    endpoint                    = var.use_localstack ? "http://localhost:45678" : null
    iam_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    sts_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    skip_credentials_validation = var.use_localstack
    skip_metadata_api_check     = var.use_localstack
    use_path_style              = var.use_localstack
  }
}

locals {
  redis_key                                = "session"
  lambda_code_signing_configuration_arn    = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  bulk_user_email_table_encryption_key_arn = data.terraform_remote_state.shared.outputs.bulk_user_email_table_encryption_key_arn
  user_profile_encryption_policy_arn       = data.terraform_remote_state.shared.outputs.user_profile_encryption_policy_arn
  user_profile_kms_key_arn                 = data.terraform_remote_state.shared.outputs.user_profile_kms_key_arn
}
