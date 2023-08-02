data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket                      = var.common_state_bucket
    key                         = "${var.environment}-shared-terraform.tfstate"
    role_arn                    = var.deployer_role_arn
    region                      = var.aws_region
    skip_credentials_validation = false
    skip_metadata_api_check     = false
    force_path_style            = false
  }
}

locals {
  redis_key                             = "session"
  lambda_code_signing_configuration_arn = data.terraform_remote_state.shared.outputs.lambda_code_signing_configuration_arn
}
