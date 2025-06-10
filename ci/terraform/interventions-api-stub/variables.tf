variable "environment" {
  type = string
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
  type        = bool
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
  type    = string
}

variable "cloudwatch_log_retention" {
  default     = 30
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
  type    = number
}

variable "scaling_trigger" {
  default = 0.6
  type    = number
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
  default     = "./artifacts/interventions-api-stub.zip"
  description = "Location of the Lambda ZIP file - defaults to build output folder when built locally"
  type        = string
}

variable "orchestration_vpc_endpoint_id" {
  description = "ID of the VPC endpoint in the orchestration VPC to permit access"
  type        = string
  default     = ""
}

variable "new_auth_api_vpc_endpoint_id" {
  description = "The ID of the Execute API Gateway vpc endpoint in the new Auth account"
  type        = string
  default     = ""
}

variable "dynamo_deletion_protection_enabled" {
  type    = bool
  default = false
}

locals {
  default_performance_parameters = {
    memory          = var.endpoint_memory_size
    concurrency     = var.lambda_min_concurrency
    max_concurrency = var.lambda_max_concurrency
    scaling_trigger = var.scaling_trigger
  }
}

variable "vpc_environment" {
  description = "The name of the environment this environment is sharing the VPC , this var is only for Authdevs env and must be overide using Authdevs.tfvars, default value should be null always."
  type        = string
  default     = null
}

variable "auth_new_account_id" {
  type        = string
  description = "Account id of the auth new AWS account"
  default     = ""
}
