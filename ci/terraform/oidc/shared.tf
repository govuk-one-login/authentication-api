
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
  external_redis_host              = var.use_localstack ? var.external_redis_host : data.terraform_remote_state.shared.aws_elasticache_replication_group.sessions_store[0].primary_endpoint_address
  external_redis_port              = var.use_localstack ? var.external_redis_port : data.terraform_remote_state.shared.aws_elasticache_replication_group.sessions_store[0].port
  external_redis_password          = var.use_localstack ? var.external_redis_password : data.terraform_remote_state.shared.random_password.redis_password.result
  authentication_security_group_id = var.use_localstack ? var.authentication_security_group_id : data.terraform_remote_state.shared.aws_vpc.authentication.default_security_group_id
  authentication_subnet_ids        = var.use_localstack ? var.authentication_subnet_ids : data.terraform_remote_state.shared.aws_subnet.authentication.*.id
  lambda_iam_role_arn              = var.use_localstack ? var.lambda_iam_role_arn : data.terraform_remote_state.shared.aws_iam_role.lambda_iam_role.arn
  lambda_iam_role_name             = var.use_localstack ? var.lambda_iam_role_name : data.terraform_remote_state.shared.aws_iam_role.lambda_iam_role.name
  dynamo_sqs_lambda_iam_role_arn   = var.use_localstack ? var.dynamo_sqs_lambda_iam_role_arn : data.terraform_remote_state.shared.aws_iam_role.dynamo_sqs_lambda_iam_role.arn
  dynamo_sqs_lambda_iam_role_name  = var.use_localstack ? var.dynamo_sqs_lambda_iam_role_name : data.terraform_remote_state.shared.aws_iam_role.dynamo_sqs_lambda_iam_role.name
  sqs_lambda_iam_role_arn          = var.use_localstack ? var.sqs_lambda_iam_role_arn : data.terraform_remote_state.shared.aws_iam_role.sqs_lambda_iam_role.arn
  sqs_lambda_iam_role_name         = var.use_localstack ? var.sqs_lambda_iam_role_name : data.terraform_remote_state.shared.aws_iam_role.sqs_lambda_iam_role.name
  email_lambda_iam_role_arn        = var.use_localstack ? var.email_lambda_iam_role_arn : data.terraform_remote_state.shared.aws_iam_role.email_lambda_iam_role.arn
  token_lambda_iam_role_arn        = var.use_localstack ? var.token_lambda_iam_role_arn : data.terraform_remote_state.shared.aws_iam_role.token_lambda_iam_role.arn
  id_token_signing_key_alias_name  = var.use_localstack ? var.id_token_signing_key_alias_name : data.terraform_remote_state.shared.aws_kms_alias.id_token_signing_key_alias.name
}
