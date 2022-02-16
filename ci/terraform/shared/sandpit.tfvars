environment                 = "sandpit"
common_state_bucket         = "digital-identity-dev-tfstate"
keep_lambdas_warm           = false
redis_node_size             = "cache.t2.micro"
test_client_email_allowlist = "testclient.user1@digital.cabinet-office.gov.uk,testclient.user2@digital.cabinet-office.gov.uk"
password_pepper             = "fake-pepper"

enable_api_gateway_execution_request_tracing = true
di_tools_signing_profile_version_arn         = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"