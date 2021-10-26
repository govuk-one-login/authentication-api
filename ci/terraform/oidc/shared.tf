
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
  external_redis_host                    = var.use_localstack ? var.external_redis_host : data.terraform_remote_state.shared.outputs.redis_host
  external_redis_port                    = var.use_localstack ? var.external_redis_port : data.terraform_remote_state.shared.outputs.redis_port
  external_redis_password                = var.use_localstack ? var.external_redis_password : data.terraform_remote_state.shared.outputs.redis_password
  authentication_vpc_arn                 = data.terraform_remote_state.shared.outputs.authentication_vpc_arn
  authentication_security_group_id       = data.terraform_remote_state.shared.outputs.authentication_security_group_id
  authentication_subnet_ids              = data.terraform_remote_state.shared.outputs.authentication_subnet_ids
  lambda_iam_role_arn                    = data.terraform_remote_state.shared.outputs.lambda_iam_role_arn
  lambda_iam_role_name                   = data.terraform_remote_state.shared.outputs.lambda_iam_role_name
  dynamo_sqs_lambda_iam_role_arn         = data.terraform_remote_state.shared.outputs.dynamo_sqs_lambda_iam_role_arn
  dynamo_sqs_lambda_iam_role_name        = data.terraform_remote_state.shared.outputs.dynamo_sqs_lambda_iam_role_name
  sqs_lambda_iam_role_arn                = data.terraform_remote_state.shared.outputs.sqs_lambda_iam_role_arn
  sqs_lambda_iam_role_name               = data.terraform_remote_state.shared.outputs.sqs_lambda_iam_role_name
  email_lambda_iam_role_arn              = data.terraform_remote_state.shared.outputs.email_lambda_iam_role_arn
  token_lambda_iam_role_arn              = data.terraform_remote_state.shared.outputs.token_lambda_iam_role_arn
  id_token_signing_key_alias_name        = data.terraform_remote_state.shared.outputs.id_token_signing_key_alias_name
  audit_signing_key_alias_name           = data.terraform_remote_state.shared.outputs.audit_signing_key_alias_name
  sms_bucket_name                        = data.terraform_remote_state.shared.outputs.sms_bucket_name
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  events_topic_encryption_key_arn        = data.terraform_remote_state.shared.outputs.events_topic_encryption_key_arn
}