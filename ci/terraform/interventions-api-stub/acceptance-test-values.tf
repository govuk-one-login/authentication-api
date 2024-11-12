resource "aws_ssm_parameter" "stub_account_interventions_table" {
  name  = "/acceptance-tests/${var.environment}/ACCOUNT_INTERVENTIONS_TABLE"
  type  = "String"
  value = aws_dynamodb_table.stub_account_interventions_table.arn
}
import {
  to = aws_ssm_parameter.stub_account_interventions_table
  id = "/acceptance-tests/${var.environment}/ACCOUNT_INTERVENTIONS_TABLE"
}
