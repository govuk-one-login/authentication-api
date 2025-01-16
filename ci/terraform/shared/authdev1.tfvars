environment         = "authdev1"
common_state_bucket = "di-auth-development-tfstate"
redis_node_size     = "cache.t2.micro"
password_pepper     = "fake-pepper"
vpc_environment     = "dev"

enable_api_gateway_execution_request_tracing = true
di_tools_signing_profile_version_arn         = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"

orch_stub_deployed = false
stub_rp_clients = [
  {
    client_name           = "di-auth-stub-relying-party-authdev1"
    at_client             = true # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://rp-dev.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-dev.build.stubs.account.gov.uk/signed-out",
    ]
    test_client = "1"
    client_type = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
      "am"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = false
  },
  {
    // this client may or may not work. It's needed for the SSM parameter generation though, so this could be classed as a dummy entry.
    client_name           = "relying-party-stub-authdev1-app"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://doc-app-rp-dev.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-dev.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client = "1"
    client_type = "app"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
      "doc-checking-app"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = false
  },
]

logging_endpoint_enabled = false
enforce_code_signing     = false

orchestration_account_id = "816047645251"

lambda_min_concurrency = 0
lambda_max_concurrency = 0
shared_use_snapstart   = true
