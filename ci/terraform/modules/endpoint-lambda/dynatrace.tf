locals {
  dynatrace_layer_arn = var.dynatrace_secret.JAVA_LAYER
  dynatrace_environment_variables = {
    AWS_LAMBDA_EXEC_WRAPPER = "/opt/dynatrace"

    DT_CONNECTION_AUTH_TOKEN     = var.dynatrace_secret.DT_CONNECTION_AUTH_TOKEN
    DT_CONNECTION_BASE_URL       = var.dynatrace_secret.DT_CONNECTION_BASE_URL
    DT_CLUSTER_ID                = var.dynatrace_secret.DT_CLUSTER_ID
    DT_TENANT                    = var.dynatrace_secret.DT_TENANT
    DT_LOG_COLLECTION_AUTH_TOKEN = var.dynatrace_secret.DT_LOG_COLLECTION_AUTH_TOKEN

    DT_OPEN_TELEMETRY_ENABLE_INTEGRATION                                   = "true"
    OTEL_INSTRUMENTATION_AWS_SDK_EXPERIMENTAL_USE_PROPAGATOR_FOR_MESSAGING = "true"
  }
}
