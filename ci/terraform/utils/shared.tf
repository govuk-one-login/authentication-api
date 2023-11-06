data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket   = var.shared_state_bucket
    key      = "${var.environment}-shared-terraform.tfstate"
    role_arn = var.deployer_role_arn
    region   = var.aws_region
  }
}

locals {
  cloudwatch_encryption_key_arn            = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  bulk_user_email_table_encryption_key_arn = data.terraform_remote_state.shared.outputs.bulk_user_email_table_encryption_key_arn
  lambda_env_vars_encryption_kms_key_arn   = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  lambda_code_signing_configuration_arn    = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  authentication_vpc_arn                   = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
  authentication_subnet_ids                = data.terraform_remote_state.shared.outputs.authentication_subnet_ids
  authentication_security_group_id         = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  authentication_egress_security_group_id  = data.terraform_remote_state.shared.outputs.authentication_egress_security_group_id
  default_performance_parameters = {
    memory  = 1024,
    timeout = 900,
  }
  common_passwords_encryption_policy_arn   = data.terraform_remote_state.shared.outputs.common_passwords_encryption_policy_arn
}
