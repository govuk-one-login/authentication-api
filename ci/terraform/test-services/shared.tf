data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket      = var.shared_state_bucket
    key         = "${var.environment}-shared-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  lambda_code_signing_configuration_arn  = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  authentication_vpc_arn                 = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
  authentication_private_subnet_ids      = data.terraform_remote_state.shared.outputs.authentication_private_subnet_ids
  authentication_security_group_id       = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  user_profile_kms_key_arn               = data.terraform_remote_state.shared.outputs.user_profile_kms_key_arn
  user_credentials_encryption_policy_arn = data.terraform_remote_state.shared.outputs.user_credentials_encryption_policy_arn

  slack_event_sns_topic_arn = data.terraform_remote_state.shared.outputs.slack_event_sns_topic_arn
  aws_account_alias         = data.terraform_remote_state.shared.outputs.aws_account_alias
}
