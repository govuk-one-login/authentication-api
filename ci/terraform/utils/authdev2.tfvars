shared_state_bucket = "di-auth-development-tfstate"

# App-specific
internal_sector_uri   = "https://identity.authdev2.dev.account.gov.uk"
allow_bulk_test_users = true

bulk_user_email_audience_loader_schedule_enabled  = false
bulk_user_email_max_audience_load_user_count      = 10
bulk_user_email_max_audience_load_user_batch_size = 2
bulk_user_email_type                              = "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL"
bulk_user_email_audience_load_pause_duration      = 1000

bulk_user_email_send_schedule_enabled    = false
bulk_user_email_send_schedule_expression = "rate(3 minutes)"
bulk_user_email_email_sending_enabled    = true
bulk_user_email_batch_size               = 2
bulk_user_email_send_mode                = "PENDING"
bulk_user_email_sender_type              = "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET"

# Logging
cloudwatch_log_retention = 30

vpc_environment = "dev"

# Sizing
email_check_results_writer_provisioned_concurrency = 0
