locals {
  dynatrace_production_secret    = "arn:aws:secretsmanager:eu-west-2:216552277552:secret:DynatraceProductionVariables"
  dynatrace_nonproduction_secret = "arn:aws:secretsmanager:eu-west-2:216552277552:secret:DynatraceNonProductionVariables"

  dynatrace_secret = jsondecode(data.aws_secretsmanager_secret_version.dynatrace_secret.secret_string)
  dynatrace_secret_new_dynatrace = {
    JAVA_LAYER = "arn:aws:lambda:eu-west-2:216552277552:layer:Dynatrace_OneAgent_1_295_65_20240730-092325_with_collector_java:1"

    DT_CONNECTION_AUTH_TOKEN     = local.dynatrace_secret["DT_CONNECTION_AUTH_TOKEN"]
    DT_CONNECTION_BASE_URL       = local.dynatrace_secret["DT_CONNECTION_BASE_URL"]
    DT_CLUSTER_ID                = local.dynatrace_secret["DT_CLUSTER_ID"]
    DT_TENANT                    = local.dynatrace_secret["DT_TENANT"]
    DT_LOG_COLLECTION_AUTH_TOKEN = local.dynatrace_secret["DT_LOG_COLLECTION_AUTH_TOKEN"]
  }

  extra_dt_envars = {
    DT_LOGGING_DESTINATION = "stdout"
    DT_LOGGING_JAVA_FLAGS  = "log-Transformer=true,log-OpenTelemetryUtils=true,log-AsyncClassRetransformer=true,log-ClassValue=true"
  }
}

data "aws_secretsmanager_secret" "dynatrace_secret" {
  arn = var.environment == "production" ? local.dynatrace_production_secret : local.dynatrace_nonproduction_secret
}
data "aws_secretsmanager_secret_version" "dynatrace_secret" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_secret.id
}
