shared_state_bucket = "digital-identity-dev-tfstate"

# URIs
internal_sector_uri = "https://identity.build.account.gov.uk"

# Signing Keys
orch_to_auth_public_signing_key      = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENRdvNXHwk1TvrgFUsWXAE5oDTcPrCBp6HxbvYDLsqwNHiDFEzCwvbXKY2QQR/Rtel0o156CtU9k1lCZJGAsSIA=="
orch_stub_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmzWAucozlF6eykmgikXj2kI03O7VWwuA51+3Ak+stF2dddC60WXEKhrFumKBUnE5GhJNg4v0iN948Mwl+vz5Xw=="

# VPC
orch_api_vpc_endpoint_id     = "vpce-0867442e4d95fb43e"
new_auth_api_vpc_endpoint_id = "vpce-042c5d3d97d7438d9"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Performance Tuning
snapstart_enabled = true

# FMS
api_fms_tag_value = "authfrontendbuild"
