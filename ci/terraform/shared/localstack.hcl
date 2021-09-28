bucket       = "terraform-state"
key          = "localstack-shared-terraform.tfstate"
region       = "eu-west-2"
endpoint     = "http://localhost:45678"
iam_endpoint = "http://localhost:45678"
sts_endpoint = "http://localhost:45678"

skip_credentials_validation = true
skip_metadata_api_check     = true
force_path_style            = true