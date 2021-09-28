
data "terraform_remote_state" "shared" {
  count   = var.use_localstack ? 0 : 1
  backend = "s3"
  config = {
    bucket   = var.shared_state_bucket
    key      = var.shared_state_key
    role_arn = var.shared_state_role
    region   = var.aws_region
  }
}

locals {
  external_redis_host              = var.use_localstack ? var.external_redis_host : data.terraform_remote_state.shared[0].outputs.redis_host
  external_redis_port              = var.use_localstack ? var.external_redis_port : data.terraform_remote_state.shared[0].outputs.redis_port
  external_redis_password          = var.use_localstack ? var.external_redis_password : data.terraform_remote_state.shared[0].outputs.redis_password
  authentication_security_group_id = var.use_localstack ? var.authentication_security_group_id : data.terraform_remote_state.shared[0].outputs.authentication_security_group_id
  authentication_subnet_ids        = var.use_localstack ? var.authentication_subnet_ids : data.terraform_remote_state.shared[0].outputs.authentication_subnet_ids
  lambda_iam_role_arn              = var.use_localstack ? var.lambda_iam_role_arn : data.terraform_remote_state.shared[0].outputs.lambda_iam_role_arn
  lambda_iam_role_name             = var.use_localstack ? var.lambda_iam_role_name : data.terraform_remote_state.shared[0].outputs.lambda_iam_role_name
  dynamo_sqs_lambda_iam_role_arn   = var.use_localstack ? var.dynamo_sqs_lambda_iam_role_arn : data.terraform_remote_state.shared[0].outputs.dynamo_sqs_lambda_iam_role_arn
  dynamo_sqs_lambda_iam_role_name  = var.use_localstack ? var.dynamo_sqs_lambda_iam_role_name : data.terraform_remote_state.shared[0].outputs.dynamo_sqs_lambda_iam_role_name
  sqs_lambda_iam_role_arn          = var.use_localstack ? var.sqs_lambda_iam_role_arn : data.terraform_remote_state.shared[0].outputs.sqs_lambda_iam_role_arn
  sqs_lambda_iam_role_name         = var.use_localstack ? var.sqs_lambda_iam_role_name : data.terraform_remote_state.shared[0].outputs.sqs_lambda_iam_role_name
  email_lambda_iam_role_arn        = var.use_localstack ? var.email_lambda_iam_role_arn : data.terraform_remote_state.shared[0].outputs.email_lambda_iam_role_arn
  token_lambda_iam_role_arn        = var.use_localstack ? var.token_lambda_iam_role_arn : data.terraform_remote_state.shared[0].outputs.token_lambda_iam_role_arn
  id_token_signing_key_alias_name  = var.use_localstack ? var.id_token_signing_key_alias_name : data.terraform_remote_state.shared[0].outputs.id_token_signing_key_alias_name
}