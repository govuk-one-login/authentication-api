auth_ext_lambda_zip_file = "./artifacts/auth-external-api.zip"
shared_state_bucket      = "di-auth-staging-tfstate"
logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]
internal_sector_uri    = "https://identity.staging.account.gov.uk"
lambda_max_concurrency = 10
lambda_min_concurrency = 3
endpoint_memory_size   = 1536
scaling_trigger        = 0.6

orch_client_id                       = "orchestrationAuth"
orch_to_auth_public_signing_key      = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5PP1PZmhiuHR57ZEfZXARt9/uiG+KKF+S7us4zEEEmEXZFR1H+kWP5RrLHQy9esxsul9X7V4pygDTY1I6QbMGg=="
orch_stub_to_auth_public_signing_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw3VqLzY6ZFWmqruOpvMpPH8PWuQQ1zSWSgFy2sngA1GKybC0zuZluGHfZMnr/BGo+teQzbDCekLijPvlozXY1g=="
orch_api_vpc_endpoint_id             = "vpce-0a81481bcd8257f5e"
new_auth_api_vpc_endpoint_id         = "vpce-07078f5f005fe5efc"
