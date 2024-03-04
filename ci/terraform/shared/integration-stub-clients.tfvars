stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-integration"
    callback_urls = [
      "https://di-auth-stub-relying-party-integration.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-integration.london.cloudapps.digital/signed-out",
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
    client_name = "di-auth-stub-relying-party-integration-app"
    callback_urls = [
      "https://di-auth-stub-relying-party-integration-app.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-integration-app.london.cloudapps.digital/signed-out",
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
    client_name = "relying-party-stub-integration"
    callback_urls = [
      "https://rp-integration.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-integration.build.stubs.account.gov.uk/signed-out",
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
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name = "relying-party-stub-integration-app"
    callback_urls = [
      "https://doc-app-rp-integration.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-integration.build.stubs.account.gov.uk/signed-out",
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
]
