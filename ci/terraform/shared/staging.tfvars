
common_state_bucket = "di-auth-staging-tfstate"

# Account IDs
orchestration_account_id = "590183975515"
tools_account_id         = "706615647326"
auth_new_account_id      = "851725205974"

# CIDR blocks
orch_privatesub_cidr_blocks       = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks     = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]

# App Specific
di_tools_signing_profile_version_arn = "arn:aws:signer:eu-west-2:114407264696:/signing-profiles/di_auth_lambda_signing_20220215170204371800000001/zLiNn2Hi1I"
orch_stub_deployed                   = false

# Sizing
redis_node_size              = "cache.m4.xlarge"
provision_dynamo             = false
provision_test_client_secret = true
