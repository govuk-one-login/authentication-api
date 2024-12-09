data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket      = var.common_state_bucket
    key         = "${var.environment}-shared-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  redis_key                                = "session"
  lambda_code_signing_configuration_arn    = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  bulk_user_email_table_encryption_key_arn = data.terraform_remote_state.shared.outputs.bulk_user_email_table_encryption_key_arn
  user_profile_encryption_policy_arn       = data.terraform_remote_state.shared.outputs.user_profile_encryption_policy_arn
  user_profile_kms_key_arn                 = data.terraform_remote_state.shared.outputs.user_profile_kms_key_arn
}
