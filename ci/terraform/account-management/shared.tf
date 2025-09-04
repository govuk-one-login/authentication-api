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
  lambda_code_signing_configuration_arn           = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  account_modifiers_encryption_policy_arn         = data.terraform_remote_state.shared.outputs.account_modifiers_encryption_policy_arn
  common_passwords_encryption_policy_arn          = data.terraform_remote_state.shared.outputs.common_passwords_encryption_policy_arn
  client_registry_encryption_policy_arn           = data.terraform_remote_state.shared.outputs.client_registry_encryption_policy_arn
  user_profile_encryption_policy_arn              = data.terraform_remote_state.shared.outputs.user_profile_encryption_policy_arn
  user_credentials_kms_key_arn                    = data.terraform_remote_state.shared.outputs.user_credentials_kms_key_arn
  pending_email_check_queue_id                    = data.terraform_remote_state.shared.outputs.pending_email_check_queue_id
  pending_email_check_queue_access_policy_arn     = data.terraform_remote_state.shared.outputs.pending_email_check_queue_access_policy_arn
  client_registry_encryption_key_arn              = data.terraform_remote_state.shared.outputs.client_registry_encryption_key_arn
  user_profile_kms_key_arn                        = data.terraform_remote_state.shared.outputs.user_profile_kms_key_arn
  email_check_results_encryption_policy_arn       = data.terraform_remote_state.shared.outputs.email_check_results_encryption_policy_arn
  test_client_allow_list_secret_access_policy_arn = data.terraform_remote_state.shared.outputs.test_client_allow_list_secret_access_policy_arn


  slack_event_sns_topic_arn = data.terraform_remote_state.shared.outputs.slack_event_sns_topic_arn
  aws_account_alias         = data.terraform_remote_state.shared.outputs.aws_account_alias
}
