environment         = "authdev2"
common_state_bucket = "di-auth-development-tfstate"
redis_node_size     = "cache.t2.micro"
password_pepper     = "fake-pepper"

enable_api_gateway_execution_request_tracing = true
di_tools_signing_profile_version_arn         = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"

stub_rp_clients = []

logging_endpoint_enabled = false
enforce_code_signing     = false
