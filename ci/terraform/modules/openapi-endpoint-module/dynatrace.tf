data "aws_secretsmanager_secret" "dynatrace_secret" {
  count = var.dynatrace_secret_string == null ? 0 : 1
  arn   = var.environment == "production" ? local.dynatrace_production_secret : local.dynatrace_nonproduction_secret
}
data "aws_secretsmanager_secret_version" "dynatrace_secret" {
  count     = var.dynatrace_secret_string == null ? 0 : 1
  secret_id = data.aws_secretsmanager_secret.dynatrace_secret[count.index].id
}

locals {
  dynatrace_layer_arn = local.dynatrace_secret["JAVA_LAYER"]
  dynatrace_environment_variables = {
    AWS_LAMBDA_EXEC_WRAPPER = "/opt/dynatrace"

    DT_CONNECTION_AUTH_TOKEN     = local.dynatrace_secret["DT_CONNECTION_AUTH_TOKEN"]
    DT_CONNECTION_BASE_URL       = local.dynatrace_secret["DT_CONNECTION_BASE_URL"]
    DT_CLUSTER_ID                = local.dynatrace_secret["DT_CLUSTER_ID"]
    DT_TENANT                    = local.dynatrace_secret["DT_TENANT"]
    DT_LOG_COLLECTION_AUTH_TOKEN = local.dynatrace_secret["DT_LOG_COLLECTION_AUTH_TOKEN"]

    DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
  }

  dynatrace_production_secret    = "arn:aws:secretsmanager:eu-west-2:216552277552:secret:DynatraceProductionVariables"
  dynatrace_nonproduction_secret = "arn:aws:secretsmanager:eu-west-2:216552277552:secret:DynatraceNonProductionVariables"

  dynatrace_secret_string = var.dynatrace_secret_string == null ? data.aws_secretsmanager_secret_version.dynatrace_secret[count.index].secret_string : var.dynatrace_secret_string
  dynatrace_secret        = jsondecode(local.dynatrace_secret_string)
}
