locals {
  audit_signing_key_alias_name = data.terraform_remote_state.shared.outputs.audit_signing_key_alias_name
  audit_signing_key_arn        = data.terraform_remote_state.shared.outputs.audit_signing_key_arn
}
