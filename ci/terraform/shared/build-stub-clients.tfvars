stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-build"
    callback_urls = [
      "http://localhost:8081/oidc/authorization-code/callback",
      "https://di-auth-stub-relying-party-build.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = []
    test_client = "0"
  },
  {
    client_name = "di-auth-stub-relying-party-build-s2"
    callback_urls = [
      "https://di-auth-stub-relying-party-build-s2.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = []
    test_client = "1"
  },
]