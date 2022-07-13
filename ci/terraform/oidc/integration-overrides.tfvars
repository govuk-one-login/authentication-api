doc_app_api_enabled                = true
doc_app_cri_data_endpoint          = "credentials/issue"
doc_app_backend_uri                = "https://integration-doc-app-cri-stub.london.cloudapps.digital"
doc_app_domain                     = "https://integration-doc-app-cri-stub.london.cloudapps.digital"
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.integration.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri          = "https://integration-doc-app-cri-stub.london.cloudapps.digital/authorize"
doc_app_jwks_endpoint              = "https://integration-doc-app-cri-stub.london.cloudapps.digital/.well-known/jwks.json"
doc_app_encryption_key_id          = "901782c72bc54c00838dadeedead04d1f4af27c689ea445faa4bed608be63781"
doc_app_signing_key_id             = "024d02ebde444847b9886d09a0836fe14cd1b8046ba84fa3bcc0f4a9bea0ce3f"

ipv_api_enabled                = true
ipv_capacity_allowed           = true
ipv_authorisation_client_id    = "authOrchestrator"
ipv_authorisation_uri          = "https://identity.integration.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri = "https://oidc.integration.account.gov.uk/ipv-callback"
ipv_backend_uri                = "https://api.identity.integration.account.gov.uk"
ipv_audience                   = "https://identity.integration.account.gov.uk"
ipv_sector                     = "https://identity.integration.account.gov.uk"
spot_enabled                   = true
ipv_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzgTML6YZ+XUEPQprWBlW
oZ9FwasmRGsdLHLgAhyNWDw4PtYaihhpSOxoI+86IeO1qAe1nfqrFGW+X37jxDBz
clY/TxQkivEQqLCWmohuFcpn5dxz6SSC+WFhwLtedC8gXUv1JP4E0mgr7OKWh7t3
RQcpGyTaAGXh2wywZXytVOLDcwwPb0PeFiC8MR0A8tIpYyx1yXjKcs1Aga8Xy0HF
V9pU5gbB7a/XLl7j3CHePsfImYi4wG17y+jbN7+vF3GDpAqyRa78ctTZT9/WBWzP
cX8yiRmHf7ID9br2MsdrTO9YyVWfI0z7OZB1GnNe5lJhGBXvd3xg4UjWbnHikliE
NQIDAQAB
-----END PUBLIC KEY-----
EOT
logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prod",
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

performance_tuning = {
  register = {
    memory          = 512
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }

  update = {
    memory          = 512
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }
}
lambda_max_concurrency = 0
lambda_min_concurrency = 1
keep_lambdas_warm      = false
endpoint_memory_size   = 1024
scaling_trigger        = 0.6
