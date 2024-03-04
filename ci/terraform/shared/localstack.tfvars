environment           = "local"
aws_endpoint          = "http://localhost:45678"
aws_dynamodb_endpoint = "http://localhost:8000"
use_localstack        = true
stub_rp_clients = [
  {
    client_name           = "di-auth-stub-relying-party-local"
    sector_identifier_uri = "https://di-auth-stub-relying-party-build.london.cloudapps.digital"
    callback_urls = [
      "http://localhost:8081/oidc/authorization-code/callback",
      "https://di-auth-stub-relying-party-build.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = []
    test_client = "1"
  },
  {
    client_name = "di-auth-stub-relying-party-local-s2"
    callback_urls = [
      "http://localhost:8082/oidc/authorization-code/callback",
      "https://di-auth-stub-relying-party-build.london.cloudapps.digital/oidc/authorization-code/callback",
    ]
    logout_urls = []
    test_client = "0"
  },
]
test_client_email_allowlist = "testclient.user1@digital.cabinet-office.gov.uk,testclient.user2@digital.cabinet-office.gov.uk"
terms_and_conditions        = "1.0"
password_pepper             = "fake-pepper"
