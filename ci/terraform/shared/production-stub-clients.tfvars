stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-production"
    callback_urls = [
      "https://di-auth-stub-relying-party-production.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = [
      "https://di-auth-stub-relying-party-production.london.cloudapps.digital/signed-out",
    ]
    test_client                     = "0"
    client_type                     = "web"
    identity_verification_supported = "1"
    scopes = [
      "openid",
      "email",
      "phone",
    ]
  },
]