stub_rp_clients = [
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
]
