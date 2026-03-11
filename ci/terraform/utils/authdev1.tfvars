shared_state_bucket = "di-auth-development-tfstate"

# App-specific
internal_sector_uri                                 = "https://identity.authdev1.sandpit.account.gov.uk"
allow_bulk_test_users                               = true
bulk_user_email_send_schedule_enabled               = false
bulk_user_email_send_schedule_expression            = "cron(0 15 ? * FRI 2049)"
bulk_user_email_email_sending_enabled               = true
bulk_user_email_included_terms_and_conditions       = "1.13"
bulk_user_email_max_audience_load_user_batch_size   = 100
bulk_user_email_max_audience_load_user_count        = 500
bulk_user_email_audience_loader_schedule_enabled    = false
bulk_user_email_audience_loader_schedule_expression = "cron(0 13 ? * FRI 2049)"
bulk_user_email_send_mode                           = "PENDING"
bulk_user_email_batch_query_limit                   = 50
bulk_user_email_max_batch_count                     = 5
bulk_user_email_batch_pause_duration                = 1000

# Logging
cloudwatch_log_retention = 30

vpc_environment = "dev"

# Sizing
performance_tuning = {
  bulk-user-email-send = {
    memory  = 512
    timeout = 300
  }
}

email_check_results_writer_provisioned_concurrency = 0
