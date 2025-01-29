common_state_bucket = "digital-identity-prod-tfstate"

# Account IDs
tools_account_id         = "114407264696"
orchestration_account_id = "533266965190"

# CIDR blocks
orch_privatesub_cidr_blocks   = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]

# App Specific

di_tools_signing_profile_version_arn = "arn:aws:signer:eu-west-2:114407264696:/signing-profiles/di_auth_lambda_signing_20220215170204371800000001/zLiNn2Hi1I"
dlq_alarm_threshold                  = 999999
orch_stub_deployed                   = false

# Sizing
redis_node_size  = "cache.m4.xlarge"
provision_dynamo = false
