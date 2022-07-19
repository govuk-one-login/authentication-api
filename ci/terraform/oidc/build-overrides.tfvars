doc_app_api_enabled                = true
doc_app_cri_data_endpoint          = "credentials/issue"
doc_app_backend_uri                = "https://build-doc-app-cri-stub.london.cloudapps.digital"
doc_app_domain                     = "https://build-doc-app-cri-stub.london.cloudapps.digital"
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.build.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri          = "https://build-doc-app-cri-stub.london.cloudapps.digital/authorize"
doc_app_jwks_endpoint              = "https://build-doc-app-cri-stub.london.cloudapps.digital/.well-known/jwks.json"
doc_app_encryption_key_id          = "7788bc975abd44e8b4fd7646d08ea9428476e37bff3e4365804b41cc29f8ef21"
spot_enabled                       = false

blocked_email_duration = 30

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
