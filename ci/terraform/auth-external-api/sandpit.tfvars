environment         = "sandpit"
shared_state_bucket = "digital-identity-dev-tfstate"
txma_account_id     = "12345678"

logging_endpoint_arns  = []
internal_sector_uri    = "https://identity.sandpit.account.gov.uk"
lambda_max_concurrency = 0
lambda_min_concurrency = 0
endpoint_memory_size   = 1024

orch_client_id                  = "orchestrationAuth"
orch_to_auth_public_signing_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESyWJU5s5F4jSovHsh9y133/Ogf5P
x78OrfDJqiMMI2p8Warbq0ppcbWvbihK6rAXTH7bPIeOHOeU9cKAEl5NdQ==
-----END PUBLIC KEY-----
EOT
