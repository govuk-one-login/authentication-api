data "aws_secretsmanager_secret" "dynatrace_auth_token" {
  arn = "arn:aws:secretsmanager:${local.dynatrace_account_region}:${local.dynatrace_account_id}:secret:AUTH_TOKEN-PhjBZc:SecretString:DT_CONNECTION_AUTH_TOKEN"
}
data "aws_secretsmanager_secret_version" "dynatrace_auth_token" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_auth_token.id
}

data "aws_secretsmanager_secret" "dynatrace_base_url" {
  arn = "arn:aws:secretsmanager:${local.dynatrace_account_region}:${local.dynatrace_account_id}:secret:BASE_URL-otGJKy:SecretString:DT_CONNECTION_BASE_URL"
}
data "aws_secretsmanager_secret_version" "dynatrace_base_url" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_base_url.id
}

data "aws_secretsmanager_secret" "dynatrace_cluster_id" {
  arn = "arn:aws:secretsmanager:${local.dynatrace_account_region}:${local.dynatrace_account_id}:secret:CLUSTER_ID-BTiQVl:SecretString:DT_CLUSTER_ID"
}
data "aws_secretsmanager_secret_version" "dynatrace_cluster_id" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_cluster_id.id
}

data "aws_secretsmanager_secret" "dynatrace_tenant" {
  arn = "arn:aws:secretsmanager:${local.dynatrace_account_region}:${local.dynatrace_account_id}:secret:TENANT-vB41Oz:SecretString:DT_TENANT"
}
data "aws_secretsmanager_secret_version" "dynatrace_tenant" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_tenant.id
}

locals {
  dynatrace_account_region = "eu-west-2"
  dynatrace_account_id     = "98415292996982"
  dynatrace_layer_arn      = "arn:aws:lambda:eu-west-2:985486846182:layer:DTOneAgentJavaLayer:1"
  dynatrace_environment_variables = {
    AWS_LAMBDA_EXEC_WRAPPER = "/opt/dynatrace"

    DT_CONNECTION_AUTH_TOKEN = data.aws_secretsmanager_secret_version.dynatrace_auth_token.secret_string
    DT_CONNECTION_BASE_URL   = data.aws_secretsmanager_secret_version.dynatrace_base_url.secret_string
    DT_CLUSTER_ID            = data.aws_secretsmanager_secret_version.dynatrace_cluster_id.secret_string
    DT_TENANT                = data.aws_secretsmanager_secret_version.dynatrace_tenant.secret_string

    DT_OPEN_TELEMETRY_ENABLE_INTEGRATION = "true"
  }
}
