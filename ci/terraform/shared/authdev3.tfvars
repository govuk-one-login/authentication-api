common_state_bucket = "di-auth-development-tfstate"
vpc_environment     = "dev"

# Account IDs
orchestration_account_id = "816047645251"
auth_new_account_id      = "975050272416"

# CIDR blocks
orch_privatesub_cidr_blocks   = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]

# App-specific
password_pepper = "fake-pepper"

enable_api_gateway_execution_request_tracing = true
di_tools_signing_profile_version_arn         = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"

orch_stub_deployed = false
stub_rp_clients = [
  {
    client_name           = "relying-party-stub-authdev3"
    at_client             = true
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
      "wallet-subject-id"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = true
  },
  {
    client_name           = "relying-party-stub-authdev3-app"
    at_client             = false
    sector_identifier_uri = "https://doc-app-rp-dev.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "https://rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-dev.build.stubs.account.gov.uk/signed-out",
      "https://rp-dev.build.stubs.account.gov.uk/signed-out",
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
    max_age_enabled   = true
  },
]

enforce_code_signing = false

# CIDR blocks
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]

# Sizing
redis_node_size      = "cache.t2.micro"
test_clients_enabled = true
