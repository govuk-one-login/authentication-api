shared_state_bucket = "digital-identity-prod-tfstate"

# App-specific
internal_sector_uri = "https://identity.account.gov.uk"
notify_template_map = {
  TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID                   = "173418a1-c442-4c4b-a6d1-d23f473f3dd0"
  INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL_TEMPLATE_ID = "c3331551-6814-421b-890f-dfbb9a32bb83"
}

bulk_user_email_audience_loader_schedule_enabled  = false
bulk_user_email_included_terms_and_conditions     = "1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8"
bulk_user_email_max_audience_load_user_batch_size = 0
bulk_user_email_max_audience_load_user_count      = 0
bulk_user_email_send_mode                         = "PENDING"

bulk_user_email_send_schedule_enabled = false
bulk_user_email_email_sending_enabled = false
bulk_user_email_batch_size            = 48

bulk_user_email_send_schedule_expression = "cron(0 10 5 OCT ? 2023)"

# Logging
logging_endpoint_arns    = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]
cloudwatch_log_retention = 30
