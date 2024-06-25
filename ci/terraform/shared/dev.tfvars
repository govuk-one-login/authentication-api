logging_endpoint_enabled             = false
common_state_bucket                  = "di-auth-development-tfstate"
di_tools_signing_profile_version_arn = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"
tools_account_id                     = 706615647326
orchestration_account_id             = "816047645251"

orch_privatesub_cidr_blocks   = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]

doc_app_cross_account_access_enabled                                = true
user_profile_table_cross_account_access_enabled                     = true
client_registry_table_cross_account_access_enabled                  = true
authentication_callback_userinfo_table_cross_account_access_enabled = true
identity_credentials_cross_account_access_enabled                   = true
