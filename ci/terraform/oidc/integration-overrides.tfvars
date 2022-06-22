doc_app_api_enabled                = true
doc_app_cri_data_endpoint          = "credentials/issue"
doc_app_backend_uri                = "https://integration-doc-app-cri-stub.london.cloudapps.digital"
doc_app_domain                     = "https://integration-doc-app-cri-stub.london.cloudapps.digital"
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.integration.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri          = "https://integration-doc-app-cri-stub.london.cloudapps.digital/authorize"
doc_app_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnQV8yrKnVObCMg+ZNLQ
P37gEe+fGAvaM/kAq05M10GREqk7zcIHD4i3xtKTmeJwLg/TPbPvNCQ5jWv9Zt54
HnSe0f6xSkkbAiNiqqcsYhP6v8o6p0VvvoiGZDDOw5mVsBDqi/NwOs8a476MN0Wa
hYUb9c/Wi+dYgtl89oPEYTmghIrDPm+66gAlTtn7PLST09sRQ8HgIoFGlElaJV0E
mex/gmWg215zlR4wMD+feYi8K9Impskbxa8M2Pyrwh839asByf9ybrp/IiYBWDdj
ISiWaUZiNN465RphH8VZOa0r06y04tNIoDKar1dNcU/SEkNjpV6WUJJgUmChdUyS
LwIDAQAB
-----END PUBLIC KEY-----
EOT
doc_app_cri_public_signing_key     = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUJAIhznCaDeZDtQEj4SVNSSGF5Pj
vqyuq8GafzksD3ZzdciYKgl1X4fMxWmpNLU8TaTtAlVHTM+8mtUGPmCCtA==
-----END PUBLIC KEY-----
EOT

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
