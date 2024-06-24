logging_endpoint_enabled             = false
common_state_bucket                  = "di-auth-staging-tfstate"
di_tools_signing_profile_version_arn = "arn:aws:signer:eu-west-2:114407264696:/signing-profiles/di_auth_lambda_signing_20220215170204371800000001/zLiNn2Hi1I"
tools_account_id                     = 706615647326

orchestration_account_id      = "590183975515"
orch_privatesub_cidr_blocks   = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]

user_profile_table_cross_account_access_enabled                     = true
client_registry_table_cross_account_access_enabled                  = true
authentication_callback_userinfo_table_cross_account_access_enabled = true
identity_credentials_cross_account_access_enabled                   = true
