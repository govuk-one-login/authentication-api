logging_endpoint_arn  = ""
logging_endpoint_arns = []
lambda_zip_file       = "./artifacts/account-management-api.zip"
common_state_bucket   = "di-auth-staging-tfstate"

openapi_spec_filename = "openapi_v2.yaml"

legacy_account_deletion_topic_arn     = "arn:aws:sns:eu-west-2:539729775994:UserAccountDeletion"
legacy_account_deletion_topic_key_arn = "arn:aws:kms:eu-west-2:539729775994:key/d33e9077-8d66-4f63-99a1-f90e29b4aabe"
