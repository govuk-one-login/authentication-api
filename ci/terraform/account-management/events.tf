data "aws_sns_topic" "events" {
  name = "${var.environment}-events"
}

locals {
  audit_signing_key_alias_name    = data.terraform_remote_state.shared.outputs.audit_signing_key_alias_name
  audit_signing_key_arn           = data.terraform_remote_state.shared.outputs.audit_signing_key_arn
  events_topic_encryption_key_arn = data.terraform_remote_state.shared.outputs.events_topic_encryption_key_arn
}