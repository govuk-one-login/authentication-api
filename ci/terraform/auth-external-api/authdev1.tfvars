environment         = "authdev1"
shared_state_bucket = "di-auth-development-tfstate"

logging_endpoint_arns  = []
internal_sector_uri    = "https://identity.authdev1.sandpit.account.gov.uk"
lambda_max_concurrency = 0
lambda_min_concurrency = 0
endpoint_memory_size   = 1536

orch_client_id                       = "orchestrationAuth"
orch_to_auth_public_signing_key      = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENB3csRUIdoaTHNn079Jl7JpiXzxF0p2ZIddCErxtIhGMTTqtbQZJCPesSKUVE/DQbpIko3mLoisuFgmQfFouCw=="
orch_stub_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM0ZehmrdDd89uYEFMTakbS7JgwCGXK7CAYMcVvy1pP5yV4O2mnDjYmvjZpvio2ctgOPxDuBb38QP1HD9WAOR2w=="

code_deploy_notification = false
