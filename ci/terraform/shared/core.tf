data "terraform_remote_state" "core" {
  backend = "s3"
  config = {
    bucket                      = var.common_state_bucket
    key                         = "${var.environment}-core-terraform.tfstate"
    role_arn                    = var.deployer_role_arn
    region                      = var.aws_region
    endpoint                    = var.use_localstack ? "http://localhost:45678" : null
    iam_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    sts_endpoint                = var.use_localstack ? "http://localhost:45678" : null
    skip_credentials_validation = var.use_localstack
    skip_metadata_api_check     = var.use_localstack
    force_path_style            = var.use_localstack
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
