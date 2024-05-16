auth_ext_lambda_zip_file = "./artifacts/auth-external-api.zip"
shared_state_bucket      = "di-auth-development-tfstate"
internal_sector_uri    = "https://identity.dev.account.gov.uk"
lambda_max_concurrency = 0
lambda_min_concurrency = 1
endpoint_memory_size   = 1536
scaling_trigger        = 0.6

orch_client_id                  = "orchestrationAuth"
orch_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHzG8IFx1jE1+Ul44jQk96efPknCXVxWS4PqLrKfR/31UQovFQLfyxA46uiMOvr7+0hRwFX1fQhagsIK+dfB5PA=="