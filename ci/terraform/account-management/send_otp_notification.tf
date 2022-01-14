module "send_otp_notification" {
  source = "../modules/endpoint-module"

  endpoint_name   = "send-otp-notification"
  path_part       = "send-otp-notification"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT             = var.environment
    EMAIL_QUEUE_URL         = aws_sqs_queue.email_queue.id
    DYNAMO_ENDPOINT         = var.use_localstack ? var.lambda_dynamo_endpoint : null
    LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY               = local.redis_key
    EVENTS_SNS_TOPIC_ARN    = data.aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
  }
  handler_function_name = "uk.gov.di.accountmanagement.lambda.SendOtpNotificationHandler::handleRequest"

  rest_api_id                            = aws_api_gateway_rest_api.di_account_management_api.id
  root_resource_id                       = aws_api_gateway_rest_api.di_account_management_api.root_resource_id
  execution_arn                          = aws_api_gateway_rest_api.di_account_management_api.execution_arn
  lambda_zip_file                        = var.lambda_zip_file
  authentication_vpc_arn                 = aws_vpc.account_management_vpc.arn
  security_group_ids                     = [aws_security_group.allow_vpc_resources_only.id]
  subnet_id                              = aws_subnet.account_management_subnets.*.id
  lambda_role_arn                        = module.account_notification_dynamo_sqs_role.arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  authorizer_id                          = aws_api_gateway_authorizer.di_account_management_api.id
  use_localstack                         = var.use_localstack

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