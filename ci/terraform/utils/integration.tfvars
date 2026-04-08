shared_state_bucket = "digital-identity-dev-tfstate"

internal_sector_uri   = "https://identity.integration.account.gov.uk"
allow_bulk_test_users = true

bulk_user_email_audience_loader_schedule_enabled  = false
bulk_user_email_max_audience_load_user_count      = 100000
bulk_user_email_max_audience_load_user_batch_size = 200
bulk_user_email_type                              = "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL"
bulk_user_email_audience_load_pause_duration      = 30000

bulk_user_email_send_schedule_enabled    = false
bulk_user_email_send_schedule_expression = "cron(* 8-15 ? 4 3-5 2026)"
bulk_user_email_email_sending_enabled    = false
bulk_user_email_batch_size               = 48
bulk_user_email_send_mode                = "PENDING"
bulk_user_email_sender_type              = "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]
