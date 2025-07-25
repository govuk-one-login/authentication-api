resource "aws_ssm_parameter" "at_internal_am_api" {
  name  = "/acceptance-tests/${var.environment}/INTERNAL_AM_API"
  type  = "String"
  value = "https://${local.account_management_api_fqdn}/"
}

import {
  to = aws_ssm_parameter.at_internal_am_api
  id = "/acceptance-tests/${var.environment}/INTERNAL_AM_API"
}

resource "aws_ssm_parameter" "at_email_verify_code" {
  name  = "/acceptance-tests/${var.environment}/EMAIL_VERIFY_CODE"
  type  = "String"
  value = var.test_client_verify_email_otp
}

resource "aws_ssm_parameter" "at_phone_verify_code" {
  name  = "/acceptance-tests/${var.environment}/PHONE_VERIFY_CODE"
  type  = "String"
  value = var.test_client_verify_phone_number_otp
}

resource "aws_ssm_parameter" "at_internal_sector_uri" {
  name  = "/acceptance-tests/${var.environment}/INTERNAL_SECTOR_URI"
  type  = "String"
  value = var.internal_sector_uri
}
