auth_ext_lambda_zip_file = "./artifacts/auth-external-api.zip"
shared_state_bucket      = "digital-identity-dev-tfstate"
logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]
internal_sector_uri    = "https://identity.integration.account.gov.uk"
lambda_max_concurrency = 0
lambda_min_concurrency = 1
endpoint_memory_size   = 1536
scaling_trigger        = 0.6

orch_client_id = "orchestrationAuth"
# pragma: allowlist nextline secret
orch_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzzwKLypUL89WVaeTbfBZu0Fws8T7ppx89XLVfgXIoCs2P//N5qdghvzgNIgVehQ7CkzyorO/lnRlWPfjCG4Oxw=="
orch_api_vpc_endpoint_id        = "vpce-0704b783d794cea52"
