locals {
  dt_log_dest  = var.dt_logging ? "stdout" : null
  dt_log_flags = var.dt_logging ? "log-AwsLambdaIntrospection=true,log-Transformer=true,log-OpenTelemetryUtils=true,log-AsyncClassRetransformer=true,log-ClassValue=true,log-dt-http-requests=true,log-span-content=true,log-debug-communication=true,log-debug-app-spans=true,log-debug-tags=true,log-debug-communication=true,log-debug-periodic-tasks=true" : null
}

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
    OTEL_JAVA_GLOBAL_AUTOCONFIGURE_ENABLED                                 = "true"

    DT_LOGGING_DESTINATION = local.dt_log_dest
    DT_LOGGING_JAVA_FLAGS  = local.dt_log_flags
  }
}
