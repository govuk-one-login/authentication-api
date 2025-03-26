resource "aws_ssm_parameter" "at_terms_and_conditions_version" {
  name  = "/acceptance-tests/${var.environment}/TERMS_AND_CONDITIONS_VERSION"
  type  = "String"
  value = var.terms_and_conditions
}

resource "aws_ssm_parameter" "at_email_address_format" {
  name  = "/acceptance-tests/${var.environment}/EMAIL_ADDRESS_FORMAT"
  type  = "String"
  value = local.acceptance_test_rp_client_emails.pattern
}

resource "aws_ssm_parameter" "at_sector_host" {
  name  = "/acceptance-tests/${var.environment}/SECTOR_HOST"
  type  = "String"
  value = "identity.${local.service_domain}"
}
import {
  to = aws_ssm_parameter.at_sector_host
  id = "/acceptance-tests/${var.environment}/SECTOR_HOST"
}

resource "aws_ssm_parameter" "at_rp_url" {
  name  = "/acceptance-tests/${var.environment}/RP_URL"
  type  = "String"
  value = var.orch_stub_deployed ? "https://orchstub.signin.${local.service_domain}/" : "${var.stub_rp_clients[index(var.stub_rp_clients[*].at_client, true)].sector_identifier_uri}/?relyingParty=${random_string.stub_relying_party_client_id[var.stub_rp_clients[index(var.stub_rp_clients[*].at_client, true)].client_name].result}"
}
import {
  to = aws_ssm_parameter.at_rp_url
  id = "/acceptance-tests/${var.environment}/RP_URL"
}

resource "aws_ssm_parameter" "at_rp_type" {
  name  = "/acceptance-tests/${var.environment}/STUB_RP_TYPE"
  type  = "String"
  value = var.orch_stub_deployed ? "ORCHESTRATION" : "LEGACY"
}

resource "aws_ssm_parameter" "at_doc_app_url" {
  name  = "/acceptance-tests/${var.environment}/DOC_APP_URL"
  type  = "String"
  value = var.stub_rp_clients[index(var.stub_rp_clients[*].client_name, "relying-party-stub-${var.environment}-app")].sector_identifier_uri
}
import {
  to = aws_ssm_parameter.at_doc_app_url
  id = "/acceptance-tests/${var.environment}/DOC_APP_URL"
}

resource "aws_ssm_parameter" "user_profile_table" {
  name  = "/acceptance-tests/${var.environment}/USER_PROFILE_TABLE"
  type  = "String"
  value = aws_dynamodb_table.user_profile_table.arn
}
import {
  to = aws_ssm_parameter.user_profile_table
  id = "/acceptance-tests/${var.environment}/USER_PROFILE_TABLE"
}

resource "aws_ssm_parameter" "user_credentials_table" {
  name  = "/acceptance-tests/${var.environment}/USER_CREDENTIALS_TABLE"
  type  = "String"
  value = aws_dynamodb_table.user_credentials_table.arn
}
import {
  to = aws_ssm_parameter.user_credentials_table
  id = "/acceptance-tests/${var.environment}/USER_CREDENTIALS_TABLE"
}

resource "aws_ssm_parameter" "client_registry_table" {
  name  = "/acceptance-tests/${var.environment}/CLIENT_REGISTRY_TABLE"
  type  = "String"
  value = aws_dynamodb_table.client_registry_table.arn
}

resource "aws_ssm_parameter" "at_client_id" {
  name = "/acceptance-tests/${var.environment}/CLIENT_ID"
  type = "String"
  value = random_string.stub_relying_party_client_id[local.stub_rp_client_name_pattern].result
}
