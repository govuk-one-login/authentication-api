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
  cloudwatch_encryption_key_arn = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}