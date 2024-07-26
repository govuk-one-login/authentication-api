stub_rp_clients = [
  {
    client_name           = "relying-party-stub-build"
    sector_identifier_uri = "https://rp-build.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client                     = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
      "am"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name           = "relying-party-stub-build-app"
    sector_identifier_uri = "https://doc-app-rp-build.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
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
  {
    client_name           = "relying-party-stub-build-acceptance-test"
    sector_identifier_uri = "https://acceptance-test-rp-build.build.stubs.account.gov.uk"
    callback_urls = [
      "https://acceptance-test-rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://acceptance-test-rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client                     = "1"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
      "am"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name           = "relying-party-micro-stub-build-acceptance-test"
    sector_identifier_uri = "https://acceptance-test-rp-micro-stub-build.build.stubs.account.gov.uk"
    callback_urls = [
      "http://localhost:3031/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "http://localhost:3031/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client                     = "1"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
      "am"
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
]
