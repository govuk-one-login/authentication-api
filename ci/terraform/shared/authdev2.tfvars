environment         = "authdev2"
common_state_bucket = "di-auth-development-tfstate"
redis_node_size     = "cache.t2.micro"
password_pepper     = "fake-pepper"

enable_api_gateway_execution_request_tracing = true
di_tools_signing_profile_version_arn         = "arn:aws:signer:eu-west-2:706615647326:/signing-profiles/di_auth_lambda_signing_20220214175605677200000001/ZPqg7ZUgCP"

stub_rp_clients = [
  {
    client_name           = "di-auth-stub-relying-party-authdev2"
    sector_identifier_uri = "https://rp-dev.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-dev.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-dev.build.stubs.account.gov.uk/signed-out",
    ]
    test_client                     = "1"
    client_type                     = "web"
    identity_verification_supported = "0"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
]

logging_endpoint_enabled = false
enforce_code_signing     = false
