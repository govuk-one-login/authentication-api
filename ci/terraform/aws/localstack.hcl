bucket       = "terraform-state"
key          = "localstack.tfstate"
region       = "eu-west-2"
endpoint     = "http://localhost:45678"
iam_endpoint = "http://localhost:45678"
sts_endpoint = "http://localhost:45678"

access_key                  = "mock_access_key"
secret_key                  = "mock_secret_key"
skip_credentials_validation = true
skip_metadata_api_check     = true
force_path_style            = true