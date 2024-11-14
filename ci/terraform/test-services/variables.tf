variable "deployer_role_arn" {
  default     = null
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "test_services-api-lambda_zip_file" {
  default     = "../../../test-services-api/build/distributions/test-services-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "lambda_min_concurrency" {
  default     = 1
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "environment" {
  type = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "aws_dynamodb_endpoint" {
  type    = string
  default = null
}

variable "redis_use_tls" {
  type    = string
  default = "true"
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
}

variable "logging_endpoint_enabled" {
  type        = bool
  default     = true
  description = "Whether the service should ship its Lambda logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "endpoint_memory_size" {
  default = 512
  type    = number
}

variable "synthetics_users" {
  default = ""
  type    = string
}

variable "txma_account_id" {
  default = ""
  type    = string
}
