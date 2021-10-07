environment           = "local"
aws_endpoint          = "http://localhost:45678"
aws_dynamodb_endpoint = "http://localhost:8000"
use_localstack        = true
keep_lambdas_warm     = false
stub_rp_clients = [
  {
    client_name = "di-auth-stub-relying-party-local"
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