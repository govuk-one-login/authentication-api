locals {
  dynatrace_layer_arn = "arn:aws:lambda:eu-west-2:216552277552:layer:Dynatrace_OneAgent_1_311_51_20250331-143707_with_collector_java:1"
  dynatrace_environment_variables = {
    AWS_LAMBDA_EXEC_WRAPPER = "/opt/dynatrace"

    DT_CONNECTION_AUTH_TOKEN     = var.dynatrace_secret.DT_CONNECTION_AUTH_TOKEN
    DT_CONNECTION_BASE_URL       = var.dynatrace_secret.DT_CONNECTION_BASE_URL
    DT_CLUSTER_ID                = var.dynatrace_secret.DT_CLUSTER_ID
    DT_TENANT                    = var.dynatrace_secret.DT_TENANT
    DT_LOG_COLLECTION_AUTH_TOKEN = var.dynatrace_secret.DT_LOG_COLLECTION_AUTH_TOKEN

    DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
  }
}
