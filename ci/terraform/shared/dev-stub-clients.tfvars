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