shared_state_bucket = "di-auth-staging-tfstate"

# URIs
internal_sector_uri = "https://identity.staging.account.gov.uk"

# Signing Keys
orch_to_auth_public_signing_key      = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5PP1PZmhiuHR57ZEfZXARt9/uiG+KKF+S7us4zEEEmEXZFR1H+kWP5RrLHQy9esxsul9X7V4pygDTY1I6QbMGg=="
orch_stub_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw3VqLzY6ZFWmqruOpvMpPH8PWuQQ1zSWSgFy2sngA1GKybC0zuZluGHfZMnr/BGo+teQzbDCekLijPvlozXY1g=="

# VPC
orch_api_vpc_endpoint_id     = "vpce-0a81481bcd8257f5e"
new_auth_api_vpc_endpoint_id = "vpce-07078f5f005fe5efc"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Performance Tuning
snapstart_enabled = true

# FMS
api_fms_tag_value = "authfrontendstaging"
