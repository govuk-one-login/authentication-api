locals {
  # Define the modules that will be used to create the API
  # The names of the modules are used to refer to the integration_uri when templating openapi.yaml
  endpoint_modules = {
    authenticate          = module.authenticate_openapi
    update-password       = module.update-password_openapi
    update-email          = module.update-email_openapi
    delete-account        = module.delete-account_openapi
    send-otp-notification = module.send-otp-notification_openapi
    update-phone-number   = module.update-phone-number_openapi
  }
  openapi_spec = templatefile(
    "${path.module}/openapi.yaml",
    {
      endpoint_modules       = local.endpoint_modules,
      authorizer_uri         = aws_lambda_alias.authorizer_alias.invoke_arn
      authorizer_credentials = aws_iam_role.invocation_role.arn
    }
  )
}

module "account-management_gateway_openapi" {
  source = "../modules/openapi-api-gateway"

  openapi_spec = local.openapi_spec

  api_gateway_name = "${var.environment}-account-management-openapi"
  environment      = var.environment
  tags             = local.default_tags

  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template
}

resource "aws_lambda_permission" "account-management_openapi_endpoint_execution_permission" {
  for_each      = local.endpoint_modules
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${module.account-management_gateway_openapi.api_gateway_execution_arn}/*/*"
}

module "dashboard_account-management_openapi" {
  source           = "../modules/dashboards"
  api_gateway_name = module.account-management_gateway_openapi.api_gateway_name
  use_localstack   = false
}
