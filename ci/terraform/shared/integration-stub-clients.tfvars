stub_rp_clients = [
  {
    client_name           = "relying-party-stub-integration"
    at_client             = true # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://rp-integration.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-integration.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-integration.build.stubs.account.gov.uk/signed-out",
    ]
    test_client                     = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name           = "relying-party-stub-integration-app"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://doc-app-rp-integration.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-integration.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-integration.build.stubs.account.gov.uk/signed-out",
    ]
    test_client                     = "1"
    identity_verification_supported = "1"
    client_type                     = "app"
    scopes = [
      "openid",
      "doc-checking-app",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
]
