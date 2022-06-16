variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type    = string
  default = "eu-west-2"
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "shared_state_bucket" {
  type = string
}

variable "lambda_zip_file" {
  default = "../../../audit-processors/build/distributions/audit-processors.zip"
  type    = string
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:45678/"
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

variable "audit_storage_expiry_days" {
  type        = number
  description = "How long before files in the audit store are expired (default: 7 years)"
  default     = 7 * 365
}

variable "lambda_memory_size" {
  default = 4096
  type    = number
}

variable "txma_obfuscation_secret_arn" {
  default = ""
}
