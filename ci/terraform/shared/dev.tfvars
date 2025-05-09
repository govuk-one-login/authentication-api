common_state_bucket = "di-auth-development-tfstate"

# Account IDs
tools_account_id         = "706615647326"
orchestration_account_id = "816047645251"
auth_new_account_id      = "975050272416"

# CIDR blocks
orch_privatesub_cidr_blocks       = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks     = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]

# App Specific
di_tools_signing_profile_version_arn = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"
