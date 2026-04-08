locals {
  vpc_environment = var.vpc_environment == null ? var.environment : var.vpc_environment
}

data "terraform_remote_state" "core" {
  backend = "s3"
  config = {
    bucket      = var.shared_state_bucket
    key         = "${local.vpc_environment}-core-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  allow_aws_service_access_security_group_id = data.terraform_remote_state.core.outputs.allow_aws_service_access_security_group_id
}
