environment                                       = "sandpit"
internal_sector_uri                               = "https://identity.sandpit.account.gov.uk"
shared_state_bucket                               = "digital-identity-dev-tfstate"
allow_bulk_test_users                             = true
bulk_user_email_send_schedule_enabled             = false
bulk_user_email_send_schedule_expression          = "rate(5 minutes)"
bulk_user_email_email_sending_enabled             = false
bulk_user_email_excluded_terms_and_conditions     = "1.5,1.6"
bulk_user_email_max_audience_load_user_batch_size = 5
bulk_user_email_max_audience_load_user_count      = 10
cloudwatch_log_retention                          = 1
performance_tuning = {
  bulk-user-email-send = {
    memory  = 512
    timeout = 300
  }
}