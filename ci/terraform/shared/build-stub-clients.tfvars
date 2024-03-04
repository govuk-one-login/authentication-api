stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-build"
    callback_urls = [
      "https://di-auth-stub-relying-party-build.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-build.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "0"
    consent_required                = "0"
    client_type                     = "web"
    identity_verification_supported = "1"
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
    client_name = "di-auth-stub-relying-party-build-s2"
    callback_urls = [
      "https://di-auth-stub-relying-party-build-s2.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-build-s2.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
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
    client_name = "di-auth-stub-relying-party-build-app"
    callback_urls = [
      "https://di-auth-stub-relying-party-build-app.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-build-app.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
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
    client_name = "di-auth-stub-relying-party-build-optional"
    callback_urls = [
      "https://di-auth-stub-relying-party-build-optional.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-build-optional.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service = false
    service_type      = "OPTIONAL"
  },
  {
    client_name = "di-auth-stub-relying-party-dev"
    callback_urls = [
      "https://di-auth-stub-relying-party-build-dev.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-build-dev.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
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
    client_name = "relying-party-stub-build"
    callback_urls = [
      "https://rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client                     = "0"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service     = false
    service_type          = "MANDATORY"
    sector_identifier_uri = "https://rp-build.build.stubs.account.gov.uk"
  },
  {
    client_name = "relying-party-stub-build-app"
    callback_urls = [
      "https://doc-app-rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "app"
    scopes = [
      "openid",
      "doc-checking-app",
    ]
    one_login_service     = false
    service_type          = "MANDATORY"
    sector_identifier_uri = "https://doc-app-rp-build.build.stubs.account.gov.uk"
  },
  {
    client_name = "relying-party-stub-build-acceptance-test"
    callback_urls = [
      "https://acceptance-test-rp-build.build.stubs.account.gov.uk/oidc/authorization-code/callback",
      "http://localhost:8080/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://acceptance-test-rp-build.build.stubs.account.gov.uk/signed-out",
      "http://localhost:8080/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
      "wallet-subject-id",
    ]
    one_login_service     = false
    service_type          = "MANDATORY"
    sector_identifier_uri = "https://acceptance-test-rp-build.build.stubs.account.gov.uk"
  },
]
