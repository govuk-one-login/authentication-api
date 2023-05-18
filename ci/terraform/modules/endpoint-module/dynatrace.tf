data "aws_secretsmanager_secret" "dynatrace_auth_token" {
  name = "DynatraceConnectionAuthToken"
}
data "aws_secretsmanager_secret_version" "dynatrace_auth_token" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_auth_token.id
}

data "aws_secretsmanager_secret" "dynatrace_base_url" {
  name = "DynatraceConnectionBaseURL"
}
data "aws_secretsmanager_secret_version" "dynatrace_base_url" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_base_url.id
}

data "aws_secretsmanager_secret" "dynatrace_cluster_id" {
  name = "DynatraceClusterID"
}
data "aws_secretsmanager_secret_version" "dynatrace_cluster_id" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_cluster_id.id
}

data "aws_secretsmanager_secret" "dynatrace_tenant" {
  name = "DynatraceTenant"
}
data "aws_secretsmanager_secret_version" "dynatrace_tenant" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_tenant.id
}

locals {
  dynatrace_layer_arn = "arn:aws:lambda:eu-west-2:985486846182:layer:DTOneAgentJavaLayer:1"
  dynatrace_environment_variables = {
    AWS_LAMBDA_EXEC_WRAPPER = "/opt/dynatrace"

    DT_CONNECTION_AUTH_TOKEN = data.aws_secretsmanager_secret_version.dynatrace_auth_token.secret_string
    DT_CONNECTION_BASE_URL   = data.aws_secretsmanager_secret_version.dynatrace_base_url.secret_string
    DT_CLUSTER_ID            = data.aws_secretsmanager_secret_version.dynatrace_cluster_id.secret_string
    DT_TENANT                = data.aws_secretsmanager_secret_version.dynatrace_tenant.secret_string

    DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
  }
}
