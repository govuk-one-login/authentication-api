data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket   = var.common_state_bucket
    key      = "${var.environment}-shared-terraform.tfstate"
    role_arn = var.deployer_role_arn
    region   = var.aws_region
  }
}

locals {
  lambda_code_signing_configuration_arn       = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  account_modifiers_encryption_policy_arn     = data.terraform_remote_state.shared.outputs.account_modifiers_encryption_policy_arn
  common_passwords_encryption_policy_arn      = data.terraform_remote_state.shared.outputs.common_passwords_encryption_policy_arn
  client_registry_encryption_policy_arn       = data.terraform_remote_state.shared.outputs.client_registry_encryption_policy_arn
  user_profile_encryption_policy_arn          = data.terraform_remote_state.shared.outputs.user_profile_encryption_policy_arn
  pending_email_check_queue_id                = data.terraform_remote_state.shared.outputs.pending_email_check_queue_id
  pending_email_check_queue_access_policy_arn = data.terraform_remote_state.shared.outputs.pending_email_check_queue_access_policy_arn
}
