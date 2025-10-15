resource "aws_api_gateway_rest_api" "di_authentication_frontend_api" {
  name = "${var.environment}-di-authentication-frontend-api"
}

resource "aws_api_gateway_usage_plan" "di_auth_frontend_usage_plan" {
  name = "${var.environment}-di-auth-frontend-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id
    stage  = aws_api_gateway_stage.endpoint_frontend_stage.stage_name
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_frontend_stage,
    aws_api_gateway_rest_api.di_authentication_frontend_api,
  ]
}

resource "aws_api_gateway_api_key" "di_auth_frontend_api_key" {
  name = "${var.environment}-di-auth-frontend-api-key"
}

resource "aws_secretsmanager_secret" "di_auth_frontend_api_key" {
  name = "/${var.environment}/frontend-api-key"
}

resource "aws_secretsmanager_secret_version" "example" {
  secret_id     = aws_secretsmanager_secret.di_auth_frontend_api_key.id
  secret_string = aws_api_gateway_api_key.di_auth_frontend_api_key.value
}

resource "aws_api_gateway_usage_plan_key" "di_auth_frontend_usage_plan_key" {
  key_id        = aws_api_gateway_api_key.di_auth_frontend_api_key.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.di_auth_frontend_usage_plan.id
}

resource "aws_api_gateway_resource" "auth_frontend_wellknown_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  path_part   = ".well-known"
}

locals {
  frontend_api_base_url = "https://${local.frontend_api_fqdn}/"
}

resource "aws_api_gateway_deployment" "frontend_deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.account_recovery.integration_trigger_value,
      module.account_recovery.method_trigger_value,
      module.start.integration_trigger_value,
      module.start.method_trigger_value,
      module.login.integration_trigger_value,
      module.login.method_trigger_value,
      module.mfa.integration_trigger_value,
      module.mfa.method_trigger_value,
      module.send_notification.integration_trigger_value,
      module.send_notification.method_trigger_value,
      module.signup.integration_trigger_value,
      module.signup.method_trigger_value,
      module.update_profile.integration_trigger_value,
      module.update_profile.method_trigger_value,
      module.userexists.integration_trigger_value,
      module.userexists.method_trigger_value,
      module.verify_code.integration_trigger_value,
      module.verify_code.method_trigger_value,
      module.verify_mfa_code.integration_trigger_value,
      module.verify_mfa_code.method_trigger_value,
      module.reset_password.integration_trigger_value,
      module.reset_password.method_trigger_value,
      module.reset-password-request.integration_trigger_value,
      module.reset-password-request.method_trigger_value,
      module.processing-identity.integration_trigger_value,
      module.processing-identity.method_trigger_value,
      module.orch_auth_code.integration_trigger_value,
      module.orch_auth_code.method_trigger_value,
      module.mfa_reset_storage_token_jwk.integration_trigger_value,
      module.mfa_reset_storage_token_jwk.method_trigger_value,
      module.reverification_result.integration_trigger_value,
      module.reverification_result.method_trigger_value,
      module.mfa_reset_jar_signing_jwk.integration_trigger_value,
      module.mfa_reset_jar_signing_jwk.method_trigger_value,
      module.mfa_reset_authorize.integration_trigger_value,
      module.mfa_reset_authorize.method_trigger_value,
      local.deploy_account_interventions_count == 1 ? module.account_interventions[0].integration_trigger_value : null,
      local.deploy_account_interventions_count == 1 ? module.account_interventions[0].method_trigger_value : null,
      local.deploy_reauth_user_count == 1 ? module.check_reauth_user[0].integration_trigger_value : null,
      local.deploy_reauth_user_count == 1 ? module.check_reauth_user[0].method_trigger_value : null,
      module.check_email_fraud_block[0].integration_trigger_value,
      module.check_email_fraud_block[0].method_trigger_value,
      local.account_modifiers_encryption_policy_arn,
      module.id_reverification_state.integration_trigger_value,
      module.id_reverification_state.method_trigger_value,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.account_recovery,
    module.start,
    module.login,
    module.mfa,
    module.send_notification,
    module.signup,
    module.update_profile,
    module.userexists,
    module.verify_code,
    module.verify_mfa_code,
    module.reset_password,
    module.reset-password-request,
    module.processing-identity,
    module.orch_auth_code,
    module.check_reauth_user,
    module.mfa_reset_authorize,
    module.mfa_reset_storage_token_jwk,
    module.reverification_result,
    module.mfa_reset_jar_signing_jwk,
    module.id_reverification_state
  ]
}

resource "aws_cloudwatch_log_group" "frontend_api_stage_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_authentication_frontend_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}


resource "aws_cloudwatch_log_subscription_filter" "frontend_api_execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-frontend-api-execution-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.frontend_api_stage_execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "frontend_stage_access_logs" {
  name              = "${var.environment}-frontend-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}


resource "aws_cloudwatch_log_subscription_filter" "frontend_api_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-frontend-api-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.frontend_stage_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_api_gateway_stage" "endpoint_frontend_stage" {
  deployment_id = aws_api_gateway_deployment.frontend_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.frontend_stage_access_logs.arn
    format          = local.access_logging_template
  }

  depends_on = [
    module.account_recovery,
    module.start,
    module.login,
    module.mfa,
    module.send_notification,
    module.signup,
    module.update_profile,
    module.userexists,
    module.verify_code,
    module.verify_mfa_code,
    module.reset_password,
    module.reset-password-request,
    module.processing-identity,
    module.orch_auth_code,
    module.check_reauth_user,
    module.check_email_fraud_block,
    module.mfa_reset_storage_token_jwk,
    module.reverification_result,
    module.mfa_reset_authorize,
    module.id_reverification_state,
    aws_api_gateway_deployment.deployment,
  ]

  tags = {
    "FMSRegionalPolicy" = "false"
    "CustomPolicy"      = var.frontend_api_fms_tag_value
  }
}

resource "aws_api_gateway_method_settings" "api_gateway_frontend_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  stage_name  = aws_api_gateway_stage.endpoint_frontend_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_frontend_stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "frontend_api" {
  api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  stage_name  = aws_api_gateway_stage.endpoint_frontend_stage.stage_name
  domain_name = local.frontend_api_fqdn
}


module "dashboard_frontend_api" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_authentication_frontend_api.name
}
