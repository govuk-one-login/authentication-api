module "frontend_api_ticf_cri_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-ticf-cri-role"
  vpc_arn     = local.authentication_vpc_arn
  count       = local.deploy_ticf_cri_count
  extra_tags = {
    Service = "ticf-cri"
  }
}

locals {
  # All the tuning parameters in here specifically point to any overrides for account interventions
  # This is deliberate - for now we want to scale up this lambda in tandem with account interventions, since
  # they are called in roughly the same number of places
  ticf_cri_performance_parameters = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters)
}

module "ticf_cri_lambda" {
  count  = local.deploy_ticf_cri_count
  source = "../modules/endpoint-lambda"

  endpoint_name = "ticf-cri"

  runbook_link               = "https://govukverify.atlassian.net/l/cp/UzdQFFH1"
  lambda_log_alarm_threshold = 20

  environment = var.environment

  handler_environment_variables = merge(var.notify_template_map, {
    ENVIRONMENT                   = var.environment
    TICF_CRI_SERVICE_CALL_TIMEOUT = var.ticf_cri_service_call_timeout
    TICF_CRI_SERVICE_URI          = var.ticf_cri_service_uri
  })
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.TicfCriHandler::handleRequest"
  handler_runtime       = "java17"

  memory_size                 = local.ticf_cri_performance_parameters.memory
  provisioned_concurrency     = local.ticf_cri_performance_parameters.concurrency
  max_provisioned_concurrency = local.ticf_cri_performance_parameters.max_concurrency
  scaling_trigger             = local.ticf_cri_performance_parameters.scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.frontend_api_ticf_cri_role[count.index].arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret
}





resource "aws_iam_policy" "ticf_cri_lambda_invocation_policy" {
  count       = local.deploy_ticf_cri_count
  name_prefix = "ticf-cri-lambda-invocation-policy"
  description = "IAM policy managing lambda invocation access for the TICF CRI lambda."

  policy = data.aws_iam_policy_document.ticf_cri_lambda_invocation_policy_document[count.index].json
  tags = {
    Service = "ticf-cri"
  }
}

data "aws_iam_policy_document" "ticf_cri_lambda_invocation_policy_document" {
  count = local.deploy_ticf_cri_count
  statement {
    sid    = "AllowLambdaInvocation"
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      module.ticf_cri_lambda[count.index].endpoint_lambda_alias.arn,
    ]
  }
}
