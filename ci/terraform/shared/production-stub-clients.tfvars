stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-production"
    callback_urls = [
      "https://di-auth-stub-relying-party-production.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-production.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
    client_type                     = "web"
    identity_verification_supported = "1"
    scopes = [
      "openid",
      "email",
      "phone",
    ]
  },
  {
    client_name = "di-auth-stub-relying-party-production-app"
    callback_urls = [
      "https://di-auth-stub-relying-party-production-app.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-production-app.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "1"
    consent_required                = "0"
    identity_verification_supported = "1"
    client_type                     = "app"
    scopes = [
      "openid",
      "doc-checking-app",
    ]
  },
]