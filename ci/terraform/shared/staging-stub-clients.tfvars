stub_rp_clients = [
  {
    client_name           = "relying-party-stub-staging"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://rp-staging.build.stubs.account.gov.uk"
    callback_urls = [
      "https://rp-staging.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-staging.build.stubs.account.gov.uk/signed-out",
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
    max_age_enabled   = true
  },
  {
    client_name           = "relying-party-stub-staging-app"
    at_client             = false # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://doc-app-rp-staging.build.stubs.account.gov.uk"
    callback_urls = [
      "https://doc-app-rp-staging.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-staging.build.stubs.account.gov.uk/signed-out",
    ]
    test_client = "1"
    client_type = "app"
    scopes = [
      "openid",
      "doc-checking-app",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = true
  },
  {
    client_name           = "relying-party-stub-staging-perf-test"
    at_client             = true # This client is the one used for acceptance tests. there should be exactly one of these marked as true.
    sector_identifier_uri = "https://perf-test-rp-staging.build.stubs.account.gov.uk"
    callback_urls = [
      "https://perf-test-rp-staging.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://perf-test-rp-staging.build.stubs.account.gov.uk/signed-out",
    ]
    test_client = "1"
    client_type = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
    max_age_enabled   = true
  },
]
