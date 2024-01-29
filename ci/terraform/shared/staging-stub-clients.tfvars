stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-staging"
    callback_urls = [
      "https://di-auth-stub-relying-party-staging.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-staging.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "0"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name = "di-auth-stub-relying-party-staging-app"
    callback_urls = [
      "https://di-auth-stub-relying-party-staging-app.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-staging-app.london.cloudapps.digital/signed-out",
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
    client_name = "di-auth-stub-relying-party-staging-t1"
    callback_urls = [
      "https://di-auth-stub-relying-party-staging-t1.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-staging-t1.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name = "relying-party-stub-staging"
    callback_urls = [
      "https://rp-staging.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://rp-staging.build.stubs.account.gov.uk/signed-out",
    ]
    test_client                     = "0"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "web"
    scopes = [
      "openid",
      "email",
      "phone",
    ]
    one_login_service = false
    service_type      = "MANDATORY"
  },
  {
    client_name = "relying-party-stub-staging-app"
    callback_urls = [
      "https://doc-app-rp-staging.build.stubs.account.gov.uk/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://doc-app-rp-staging.build.stubs.account.gov.uk/signed-out",
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