shared_state_bucket = "digital-identity-prod-tfstate"

# URIs
internal_sector_uri = "https://identity.account.gov.uk"

# VPC
orch_api_vpc_endpoint_id = "vpce-0dd5d6bf9c2a1eade"

# Logging
logging_endpoint_arns    = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]
cloudwatch_log_retention = 30

# Performance Tuning
snapstart_enabled = true

# FMS
api_fms_tag_value = "authfrontendprod"
