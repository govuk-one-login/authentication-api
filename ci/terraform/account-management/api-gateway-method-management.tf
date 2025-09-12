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
    mfa-methods-retrieve  = module.mfa-methods-retrieve
    mfa-methods-create    = module.mfa-methods-create
    mfa-methods-delete    = module.mfa-methods-delete
    mfa-methods-update    = module.mfa-methods-update
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

resource "local_file" "rendered_openapi" {
  filename = "${path.module}/openapi_rendered.yaml"
  content  = local.openapi_spec
}

output "rendered_openapi_spec" {
  sensitive = true
  value     = local.openapi_spec
}

data "aws_vpc" "auth_shared_vpc" {
  filter {
    name   = "tag:Name"
    values = ["${local.vpc_environment}-shared-vpc"]
  }
}

data "aws_vpc_endpoint" "auth_api_vpc_endpoint" {
  vpc_id       = data.aws_vpc.auth_shared_vpc.id
  service_name = "com.amazonaws.eu-west-2.execute-api"
  tags = {
    Environment = local.vpc_environment
    terraform   = "di-infrastructure/core"
  }
}

locals {
  api_vpc_endpoint_ids = length(var.home_vpc_endpoint_id) == 0 ? [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id] : concat([data.aws_vpc_endpoint.auth_api_vpc_endpoint.id], var.home_vpc_endpoint_id)
}

module "account-management-method_management_gateway" {
  source = "../modules/private-api-gateway"

  openapi_spec = local.openapi_spec

  api_gateway_name = "${var.environment}-di-account-management-api-method-management"
  environment      = var.environment

  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template

  vpc_endpoint_ids = local.api_vpc_endpoint_ids

  extra_tags = {
    "FMSRegionalPolicy" = "false"
    "CustomPolicy"      = var.am_api_fms_tag_value
  }

}

resource "aws_lambda_permission" "account-management-method_management_openapi_endpoint_execution_permission" {
  for_each      = local.endpoint_modules
  statement_id  = "AllowAPIGatewayInvokeMethodManagement"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${module.account-management-method_management_gateway.api_gateway_execution_arn}/*/*"

  depends_on = [
    module.account-management-method_management_gateway
  ]
}

module "dashboard_account-management-method_management_openapi" {
  source           = "../modules/dashboards"
  api_gateway_name = module.account-management-method_management_gateway.api_gateway_name
}
