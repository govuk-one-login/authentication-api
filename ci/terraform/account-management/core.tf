locals {
  vpc_environment        = var.vpc_environment == null ? var.environment : var.vpc_environment
  is_acceptance_test_env = !contains(["production", "integration"], var.environment)
}

data "terraform_remote_state" "core" {
  backend = "s3"
  config = {
    bucket      = var.common_state_bucket
    key         = "${local.vpc_environment}-core-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  vpc_arn                                    = data.terraform_remote_state.core.outputs.vpc_arn
  vpc_id                                     = data.terraform_remote_state.core.outputs.vpc_id
  allow_aws_service_access_security_group_id = data.terraform_remote_state.core.outputs.allow_aws_service_access_security_group_id
  allow_egress_security_group_id             = data.terraform_remote_state.core.outputs.allow_egress_security_group_id
  private_subnet_ids                         = data.terraform_remote_state.core.outputs.private_subnet_ids
  private_subnet_cidr_blocks                 = data.terraform_remote_state.core.outputs.private_subnet_cidr_blocks
}
