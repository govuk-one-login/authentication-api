locals {
  # Define the modules that will be used to create the API
  # The names of the modules are used to refer to the integration_uri when templating openapi.yaml
  endpoint_modules = {
    authenticate          = module.authenticate
    update-password       = module.update_password
    update-email          = module.update_email
    delete-account        = module.delete_account
    send-otp-notification = module.send_otp_notification
    update-phone-number   = module.update_phone_number
  }
  openapi_spec = templatefile(
    "${path.module}/${var.openapi_spec_filename}",
    {
      endpoint_modules       = local.endpoint_modules,
      authorizer_uri         = aws_lambda_alias.authorizer_alias.invoke_arn
      authorizer_credentials = aws_iam_role.invocation_role.arn
    }
  )
}

resource "local_file" "templated_openapi_spec" {
  content  = local.openapi_spec
  filename = "${path.module}/openapi-templated.yaml"

}


module "account-management-method_management_gateway" {
  source = "../modules/openapi-api-gateway"

  openapi_spec = local.openapi_spec

  api_gateway_name = "${var.environment}-di-account-management-api-method-management"
  environment      = var.environment
  tags             = local.default_tags

  domain_name                                  = var.use_openapi_gateway ? local.account_management_api_fqdn : ""
  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template

  waf_arns = [
    aws_wafv2_web_acl.wafregional_web_acl_am_api[local.method-management_web_acl_name].arn
  ]
}

resource "aws_lambda_permission" "account-management-method_management_openapi_endpoint_execution_permission" {
  for_each      = local.endpoint_modules
  statement_id  = "AllowAPIGatewayInvokeMethodManagement"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${module.account-management-method_management_gateway.api_gateway_execution_arn}/*/*"
}

module "dashboard_account-management-method_management_openapi" {
  count            = var.use_openapi_gateway ? 1 : 0
  source           = "../modules/dashboards"
  api_gateway_name = module.account-management-method_management_gateway.api_gateway_name
  use_localstack   = false
}