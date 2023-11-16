variable "environment" {
  type = string
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
}

variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "deployer_role_arn" {
  default     = null
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "cloudwatch_log_retention" {
  default     = 1
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "lambda_max_concurrency" {
  default = 0
}

variable "scaling_trigger" {
  default = 0.7
}

variable "lambda_min_concurrency" {
  default     = 0
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "endpoint_memory_size" {
  default = 1536
  type    = number
}

variable "interventions_api_stub_release_zip_file" {
  default     = "../../../interventions-api-stub/build/distributions/interventions-api-stub.zip"
  description = "Location of the Lambda ZIP file - defaults to build output folder when built locally"
  type        = string
}

locals {
  default_performance_parameters = {
    memory          = var.endpoint_memory_size
    concurrency     = var.lambda_min_concurrency
    max_concurrency = var.lambda_max_concurrency
    scaling_trigger = var.scaling_trigger
  }
}
