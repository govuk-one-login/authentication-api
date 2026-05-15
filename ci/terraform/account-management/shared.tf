data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket      = var.common_state_bucket
    key         = "${var.environment}-shared-terraform.tfstate"
    assume_role = var.deployer_role_arn != null ? { role_arn = var.deployer_role_arn } : null
    region      = var.aws_region
  }
}

locals {
  elasticache_alerts_sns_topic_arn = data.terraform_remote_state.shared.outputs.elasticache_alerts_sns_topic_arn
}
