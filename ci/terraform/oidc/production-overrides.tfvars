notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID         = "09f29c9a-3f34-4a56-88f5-8197aede7f85"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID  = "8babad52-0e2e-443a-8a5a-c296dc1696cc"
  EMAIL_UPDATED_TEMPLATE_ID        = "22aac1ce-38c7-45f5-97b2-26ac1a54a235"
  DELETE_ACCOUNT_TEMPLATE_ID       = "1540bdda-fdff-4297-b627-92102e061bfa"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID = "8907d080-e69c-42c6-8cf5-54ca1558a2e4"
  PASSWORD_UPDATED_TEMPLATE_ID     = "ebf3730c-0769-462b-ab39-7d9a7439bac1"
}

doc_app_api_enabled                = true
doc_app_cri_data_endpoint          = "userinfo"
doc_app_backend_uri                = "https://api-backend-api.review-b.account.gov.uk"
doc_app_domain                     = "https://api.review-b.account.gov.uk"
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri          = "https://www.review-b.account.gov.uk/dca/oauth2/authorize"
doc_app_jwks_endpoint              = "https://api-backend-api.review-b.account.gov.uk/.well-known/jwks.json"
doc_app_encryption_key_id          = "7958938d-eea0-4e6d-9ea1-ec0b9d421f77"

cloudwatch_log_retention       = 5
client_registry_api_enabled    = false
spot_enabled                   = true
ipv_api_enabled                = true
ipv_capacity_allowed           = true
ipv_authorisation_uri          = "https://identity.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri = "https://oidc.account.gov.uk/ipv-callback"
ipv_backend_uri                = "https://api.identity.account.gov.uk"
ipv_audience                   = "https://identity.account.gov.uk"
internal_sector_uri            = "https://identity.account.gov.uk"
ipv_authorisation_client_id    = "authOrchestrator"
ipv_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4K/6GH//FQSD6Yk/5nKY
zRCwrYcQy7wGHH2cZ7EXo/9+SNRcbQlzd+NVTplIk9x7+t7g8U36z/I8CM/woGgJ
zM8DNREecxH/4YEYKOqbqHSnK7iICJ18Wfb+mNr20Dt+Ik1oQja6aKPqIj4Jl4WW
0vHMhDfUNP/iOi3zhNJsTZwYjVQWqLzmWfAqO/61d2XbLDIgubKqAtTFWnxeXuBU
VZAbq03qmvzyekRUvZtck7JuQUa9mj2gJC0YPLoLDM+j0QDGWrPnDA2L2VmmF1wn
rbeA0zSUxxfdffFH/L0cTgzdTQtv6iGQrkfHnTTk1TQe0+wxJEQz5FlcXYl6qSrh
swIDAQAB
-----END PUBLIC KEY-----
EOT

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

  reset-password = {
    memory          = 1024
    concurrency     = 2
    max_concurrency = 10
    scaling_trigger = 0.5
  }

  reset-password-request = {
    memory          = 1024
    concurrency     = 2
    max_concurrency = 10
    scaling_trigger = 0.5
  }
}
lambda_max_concurrency = 10
lambda_min_concurrency = 3
endpoint_memory_size   = 1024
scaling_trigger        = 0.6

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]
