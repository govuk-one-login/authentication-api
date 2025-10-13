data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket      = var.shared_state_bucket
    key         = "${var.environment}-shared-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

data "terraform_remote_state" "oidc" {
  backend = "s3"
  config = {
    bucket      = var.shared_state_bucket
    key         = "${var.environment}-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  cloudwatch_encryption_key_arn             = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  bulk_user_email_table_encryption_key_arn  = data.terraform_remote_state.shared.outputs.bulk_user_email_table_encryption_key_arn
  lambda_env_vars_encryption_kms_key_arn    = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  lambda_code_signing_configuration_arn     = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  authentication_vpc_arn                    = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
  authentication_private_subnet_ids         = data.terraform_remote_state.shared.outputs.authentication_private_subnet_ids
  authentication_security_group_id          = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  authentication_egress_security_group_id   = data.terraform_remote_state.shared.outputs.authentication_egress_security_group_id
  user_profile_encryption_policy_arn        = data.terraform_remote_state.shared.outputs.user_profile_encryption_policy_arn
  email_check_results_encryption_policy_arn = data.terraform_remote_state.shared.outputs.email_check_results_encryption_policy_arn
  default_performance_parameters = {
    memory  = 1024,
    timeout = 900,
  }
  common_passwords_encryption_policy_arn = data.terraform_remote_state.shared.outputs.common_passwords_encryption_policy_arn
  user_profile_kms_key_arn               = data.terraform_remote_state.shared.outputs.user_profile_kms_key_arn
  user_credentials_kms_key_arn           = data.terraform_remote_state.shared.outputs.user_credentials_kms_key_arn

  slack_event_sns_topic_arn = data.terraform_remote_state.shared.outputs.slack_event_sns_topic_arn
  aws_account_alias         = data.terraform_remote_state.shared.outputs.aws_account_alias
}
