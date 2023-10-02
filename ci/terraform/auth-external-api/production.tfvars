auth_ext_lambda_zip_file = "./artifacts/auth-external-api.zip"
shared_state_bucket      = "digital-identity-prod-tfstate"
cloudwatch_log_retention = 5
logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]
internal_sector_uri    = "https://identity.account.gov.uk"
lambda_max_concurrency = 10
lambda_min_concurrency = 3
endpoint_memory_size   = 1024
scaling_trigger        = 0.6

orch_client_id                  = "orchestrationAuth"
orch_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESyWJU5s5F4jSovHsh9y133/Ogf5Px78OrfDJqiMMI2p8Warbq0ppcbWvbihK6rAXTH7bPIeOHOeU9cKAEl5NdQ=="
