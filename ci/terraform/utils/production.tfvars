shared_state_bucket = "digital-identity-prod-tfstate"

# App-specific
internal_sector_uri = "https://identity.account.gov.uk"
notify_template_map = {
  TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID = "173418a1-c442-4c4b-a6d1-d23f473f3dd0"
}

bulk_user_email_audience_loader_schedule_enabled  = false
bulk_user_email_included_terms_and_conditions     = "1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8"
bulk_user_email_max_audience_load_user_batch_size = 0
bulk_user_email_max_audience_load_user_count      = 0
bulk_user_email_send_mode                         = "PENDING"

bulk_user_email_send_schedule_enabled = true
bulk_user_email_email_sending_enabled = true
bulk_user_email_batch_query_limit     = 2500
bulk_user_email_max_batch_count       = 1
bulk_user_email_batch_pause_duration  = 0

bulk_user_email_send_schedule_expression = "cron(0 10 5 OCT ? 2023)"

# Logging
logging_endpoint_arns    = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]
cloudwatch_log_retention = 30

# SMS Quota Monitor
sms_quota_monitor_schedule_rate   = "rate(10 minutes)"
domestic_sms_quota_threshold      = "375000"
international_sms_quota_threshold = "9000"
