data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket      = var.shared_state_bucket
    key         = "${var.environment}-shared-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region

    endpoint                    = null
    iam_endpoint                = null
    sts_endpoint                = null
    skip_credentials_validation = false
    skip_metadata_api_check     = false
    use_path_style              = false
  }
}

locals {
  authentication_vpc_arn                 = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
  lambda_code_signing_configuration_arn  = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
  authentication_security_group_id       = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  authentication_private_subnet_ids      = data.terraform_remote_state.shared.outputs.authentication_private_subnet_ids
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
}
