shared_state_bucket = "digital-identity-dev-tfstate"

internal_sector_uri                           = "https://identity.integration.account.gov.uk"
allow_bulk_test_users                         = true
bulk_user_email_included_terms_and_conditions = "1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]
