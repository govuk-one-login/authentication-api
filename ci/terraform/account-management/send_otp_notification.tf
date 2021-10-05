module "send_otp_notification" {
  source = "../modules/endpoint-module"

  endpoint_name   = "send-otp-notification"
  path_part       = "send-otp-notification"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT     = var.environment
    EMAIL_QUEUE_URL = aws_sqs_queue.email_queue.id
    DYNAMO_ENDPOINT = var.use_localstack ? var.lambda_dynamo_endpoint : null
    REDIS_HOST      = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.account_management_sessions_store[0].primary_endpoint_address
    REDIS_PORT      = var.use_localstack ? var.external_redis_port : aws_elasticache_replication_group.account_management_sessions_store[0].port
    REDIS_PASSWORD  = var.use_localstack ? var.external_redis_password : random_password.redis_password.result
    REDIS_TLS       = var.redis_use_tls
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.SendOtpNotificationHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id          = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn             = aws_api_gateway_rest_api.di_account_management_api.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.account_management_vpc.default_security_group_id
  subnet_id                 = aws_subnet.account_management_subnets.*.id
  lambda_role_arn           = aws_iam_role.dynamo_sqs_lambda_iam_role.arn
  logging_endpoint_enabled  = var.logging_endpoint_enabled
  logging_endpoint_arn      = var.logging_endpoint_arn
  cloudwatch_key_arn        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention  = var.cloudwatch_log_retention
  default_tags              = local.default_tags
  authorizer_id             = aws_api_gateway_authorizer.di_account_management_api.id
  use_localstack            = var.use_localstack

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_lambda_zip_file       = var.lambda_warmer_zip_file
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  depends_on = [
    aws_api_gateway_rest_api.di_account_management_api,
    aws_vpc.account_management_vpc,
    aws_subnet.account_management_subnets,
    aws_sqs_queue.email_queue,
    aws_elasticache_replication_group.account_management_sessions_store,
  ]
}