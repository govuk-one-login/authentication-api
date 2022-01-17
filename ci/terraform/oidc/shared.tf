
data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket                      = var.shared_state_bucket
    key                         = "${var.environment}-shared-terraform.tfstate"
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
  redis_key                                   = "session"
  authentication_vpc_arn                      = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
  authentication_security_group_id            = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  authentication_egress_security_group_id     = data.terraform_remote_state.shared.outputs.authentication_egress_security_group_id
  authentication_oidc_redis_security_group_id = data.terraform_remote_state.shared.outputs.authentication_oidc_redis_security_group_id
  authentication_subnet_ids                   = data.terraform_remote_state.shared.outputs.authentication_subnet_ids
  id_token_signing_key_alias_name             = data.terraform_remote_state.shared.outputs.id_token_signing_key_alias_name
  id_token_signing_key_arn                    = data.terraform_remote_state.shared.outputs.id_token_signing_key_arn
  audit_signing_key_alias_name                = data.terraform_remote_state.shared.outputs.audit_signing_key_alias_name
  audit_signing_key_arn                       = data.terraform_remote_state.shared.outputs.audit_signing_key_arn
  sms_bucket_name                             = data.terraform_remote_state.shared.outputs.sms_bucket_name
  lambda_env_vars_encryption_kms_key_arn      = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  events_topic_encryption_key_arn             = data.terraform_remote_state.shared.outputs.events_topic_encryption_key_arn
  lambda_parameter_encryption_key_id          = data.terraform_remote_state.shared.outputs.lambda_parameter_encryption_key_id
  lambda_parameter_encryption_alias_id        = data.terraform_remote_state.shared.outputs.lambda_parameter_encryption_alias_id
  redis_ssm_parameter_policy                  = data.terraform_remote_state.shared.outputs.redis_ssm_parameter_policy
  pepper_ssm_parameter_policy                 = data.terraform_remote_state.shared.outputs.pepper_ssm_parameter_policy
  ipv_capacity_ssm_parameter_policy           = data.terraform_remote_state.shared.outputs.ipv_capacity_ssm_parameter_policy
}