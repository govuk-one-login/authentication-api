shared_state_bucket = "di-auth-development-tfstate"

# App-specific
internal_sector_uri = "https://identity.dev.account.gov.uk"

allow_bulk_test_users = true

bulk_user_email_audience_loader_schedule_enabled  = false
bulk_user_email_included_terms_and_conditions     = "1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8"
bulk_user_email_max_audience_load_user_batch_size = 1000
bulk_user_email_max_audience_load_user_count      = 5000

bulk_user_email_send_schedule_enabled = false
bulk_user_email_email_sending_enabled = false
bulk_user_email_batch_query_limit     = 25
bulk_user_email_max_batch_count       = 100
bulk_user_email_batch_pause_duration  = 0

# Sizing
email_check_results_writer_provisioned_concurrency = 0

# SMS Quota Monitor
sms_quota_monitor_schedule_rate   = "rate(10 minutes)"
domestic_sms_quota_threshold      = "600000"
international_sms_quota_threshold = "15000"
