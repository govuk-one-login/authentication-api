module "hello_world_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "hello-world-role"
  vpc_arn     = local.authentication_vpc_arn
}

module "hello_world_lambda" {
  source = "../modules/endpoint-module"

  endpoint_name   = "hello-world"
  path_part       = "hello-world"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT = var.environment
  }
  handler_function_name = "uk.gov.di.authentication.interventions.api.stub.lambda.HelloWorldHandler::handleRequest"
  handler_runtime       = "java17"

  rest_api_id      = aws_api_gateway_rest_api.interventions_api_stub.id
  root_resource_id = aws_api_gateway_rest_api.interventions_api_stub.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.interventions_api_stub.execution_arn

  memory_size                 = local.default_performance_parameters.memory
  provisioned_concurrency     = local.default_performance_parameters.concurrency
  max_provisioned_concurrency = local.default_performance_parameters.max_concurrency
  scaling_trigger             = local.default_performance_parameters.scaling_trigger

  source_bucket           = aws_s3_bucket.interventions_api_stub_source_bucket.bucket
  lambda_zip_file         = aws_s3_object.interventions_api_stub_release_zip.key
  lambda_zip_file_version = aws_s3_object.interventions_api_stub_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.hello_world_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  use_localstack = false

  depends_on = [
    aws_api_gateway_rest_api.interventions_api_stub,
  ]
}
