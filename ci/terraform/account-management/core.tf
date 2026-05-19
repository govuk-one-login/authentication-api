locals {
  vpc_environment = var.vpc_environment == null ? var.environment : var.vpc_environment
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
  vpc_id                     = data.terraform_remote_state.core.outputs.vpc_id
  private_subnet_ids         = data.terraform_remote_state.core.outputs.private_subnet_ids
  private_subnet_cidr_blocks = data.terraform_remote_state.core.outputs.private_subnet_cidr_blocks
}
