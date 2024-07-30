environment         = "authdev1"
shared_state_bucket = "di-auth-development-tfstate"

logging_endpoint_arns  = []
internal_sector_uri    = "https://identity.authdev1.sandpit.account.gov.uk"
lambda_max_concurrency = 0
lambda_min_concurrency = 0
endpoint_memory_size   = 1536

orch_client_id = "orchestrationAuth"
# pragma: allowlist nextline secret
orch_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENB3csRUIdoaTHNn079Jl7JpiXzxF0p2ZIddCErxtIhGMTTqtbQZJCPesSKUVE/DQbpIko3mLoisuFgmQfFouCw=="
