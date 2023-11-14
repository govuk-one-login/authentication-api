data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket                      = var.shared_state_bucket
    key                         = "${var.environment}-shared-terraform.tfstate"
    role_arn                    = var.deployer_role_arn
    region                      = var.aws_region
    endpoint                    = null
    iam_endpoint                = null
    sts_endpoint                = null
    skip_credentials_validation = false
    skip_metadata_api_check     = false
    force_path_style            = false
  }
}

