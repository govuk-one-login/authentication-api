module "account_interventions_stub_role" {
  source             = "../modules/lambda-role"
  environment        = var.environment
  role_name          = "account_interventions_stub-role"
  vpc_arn            = local.authentication_vpc_arn
  policies_to_attach = [aws_iam_policy.stub_interventions_dynamo_read_access.arn]
  extra_tags = {
    Service = "account-interventions-stub"
  }
}

module "account_interventions_stub_lambda" {
  source = "../modules/endpoint-lambda"

  endpoint_name = "account-interventions-stub"

  environment = var.environment

  handler_environment_variables = {
    ENVIRONMENT = var.environment
  }
  handler_function_name = "uk.gov.di.authentication.interventions.api.stub.lambda.AccountInterventionsApiStubHandler::handleRequest"
  handler_runtime       = "java17"
  architectures         = ["arm64"]

  memory_size                 = local.default_performance_parameters.memory
  provisioned_concurrency     = 0
  max_provisioned_concurrency = local.default_performance_parameters.max_concurrency
  scaling_trigger             = local.default_performance_parameters.scaling_trigger
  snapstart                   = true

  source_bucket           = aws_s3_bucket.interventions_api_stub_source_bucket.bucket
  lambda_zip_file         = aws_s3_object.interventions_api_stub_release_zip.key
  lambda_zip_file_version = aws_s3_object.interventions_api_stub_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.account_interventions_stub_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  account_alias                          = data.aws_iam_account_alias.current.account_alias
  slack_event_topic_arn                  = data.aws_sns_topic.slack_events.arn
  dynatrace_secret                       = local.dynatrace_secret
}
