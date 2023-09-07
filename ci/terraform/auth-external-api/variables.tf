variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "environment" {
  type = string
}

variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "auth_ext_lambda_zip_file" {
  default     = "../../../auth-external-api/build/distributions/auth-external-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
}