locals {
  dynatrace_production_secret    = "arn:aws:secretsmanager:eu-west-2:216552277552:secret:DynatraceProductionVariables"
  dynatrace_nonproduction_secret = "arn:aws:secretsmanager:eu-west-2:216552277552:secret:DynatraceNonProductionVariables"

  # tflint-ignore: terraform_unused_declarations
  dynatrace_secret = jsondecode(data.aws_secretsmanager_secret_version.dynatrace_secret.secret_string)
}

data "aws_secretsmanager_secret" "dynatrace_secret" {
  arn = var.environment == "production" ? local.dynatrace_production_secret : local.dynatrace_nonproduction_secret
}
data "aws_secretsmanager_secret_version" "dynatrace_secret" {
  secret_id = data.aws_secretsmanager_secret.dynatrace_secret.id
}
