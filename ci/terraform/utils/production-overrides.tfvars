cloudwatch_log_retention = 5

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

internal_sector_uri = "https://identity.account.gov.uk"

shared_state_bucket = "digital-identity-prod-tfstate"

notify_template_map = {
  TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID = "173418a1-c442-4c4b-a6d1-d23f473f3dd0"
}
