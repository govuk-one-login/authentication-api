environment         = "sandpit"
common_state_bucket = "digital-identity-dev-tfstate"
redis_node_size     = "cache.t2.micro"
password_pepper     = "fake-pepper"

enable_api_gateway_execution_request_tracing = true
di_tools_signing_profile_version_arn         = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"

stub_rp_clients = [
  {
    client_name           = "relying-party-stub-sandpit"
    sector_identifier_uri = "https://rp-dev.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-dev.build.stubs.account.gov.uk/signed-out",
    ]
    test_client                     = "0"
    client_type                     = "web"
    identity_verification_supported = "0"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name           = "relying-party-stub-sandpit-app"
    sector_identifier_uri = "https://doc-app-rp-dev.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-dev.build.stubs.account.gov.uk/signed-out",
    ]
    test_client                     = "1"
    client_type                     = "app"
    identity_verification_supported = "1"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
      "doc-checking-app"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
]

logging_endpoint_enabled = false
enforce_code_signing     = false
orchestration_account_id = "816047645251"

orch_privatesub_cidr_blocks   = ["10.1.10.0/23", "10.1.12.0/23", "10.1.14.0/23"]
orch_protectedsub_cidr_blocks = ["10.1.4.0/23", "10.1.6.0/23", "10.1.8.0/23"]

identity_credentials_cross_account_access_enabled                   = true
authentication_callback_userinfo_table_cross_account_access_enabled = true
