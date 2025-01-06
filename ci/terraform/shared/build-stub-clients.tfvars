stub_rp_clients = [
  {
    client_name           = "relying-party-stub-build"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://rp-build.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client = "0"
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
    client_name           = "relying-party-stub-build-app"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://doc-app-rp-build.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
      "https://rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
      "https://rp-build.build.stubs.account.gov.uk/signed-out",
    ]
    test_client = "1"
    client_type = "app"
    scopes = [
      "openid",
      "doc-checking-app",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = false
  },
  {
    client_name           = "relying-party-stub-build-acceptance-test"
    at_client             = true # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://acceptance-test-rp-build.build.stubs.account.gov.uk"
    callback_urls = [
      "https://acceptance-test-rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
      "https://rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://acceptance-test-rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
      "https://rp-build.build.stubs.account.gov.uk/signed-out",
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
    max_age_enabled   = true
  },
  {
    client_name           = "relying-party-micro-stub-build-acceptance-test"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://acceptance-test-rp-micro-stub-build.build.stubs.account.gov.uk"
    callback_urls = [
      "http://localhost:3031/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "http://localhost:3031/signed-out",
      "http://localhost:8080/signed-out",
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
    # New client for Secure pipeline Migration
    client_name           = "relying-party-stub-build-sp"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://rp-build-sp.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-build-sp.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
      "https://rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-build-sp.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
      "https://rp-build.build.stubs.account.gov.uk/signed-out",
    ]
    test_client = "0"
    client_type = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = false
  },
]
