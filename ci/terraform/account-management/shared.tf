data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket                      = var.common_state_bucket
    key                         = "${var.environment}-shared-terraform.tfstate"
    role_arn                    = var.deployer_role_arn
    region                      = var.aws_region
    endpoint                    = var.use_localstack ? "http://localhost:45678" : null
    iam_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    sts_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    skip_credentials_validation = var.use_localstack
    skip_metadata_api_check     = var.use_localstack
    use_path_style              = var.use_localstack
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
  client_registry_encryption_key_arn          = data.terraform_remote_state.shared.outputs.client_registry_encryption_key_arn
  user_profile_kms_key_arn                    = data.terraform_remote_state.shared.outputs.user_profile_kms_key_arn
  email_check_results_encryption_policy_arn   = data.terraform_remote_state.shared.outputs.email_check_results_encryption_policy_arn
}
