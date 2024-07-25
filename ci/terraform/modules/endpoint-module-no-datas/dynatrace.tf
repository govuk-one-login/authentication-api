locals {
  dynatrace_secret = jsondecode(var.dynatrace_secret_string)

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
}
