variable "environment" {
  description = "The environment the API Gateway is in"
  type        = string
}
variable "api_gateway_name" {
  description = "The name of the API Gateway"
  type        = string
}

variable "extra_tags" {
  description = "Additional tags to apply to created resources, in addition to the default tags from the provider. This is unlikely to be needed in most cases."
  type        = map(string)
  default     = {}
}

variable "openapi_spec" {
  description = "The content of the OpenAPI spec to deploy"
  type        = string
}

variable "vpc_endpoint_ids" {
  description = "The VPC endpoint IDs"
  type        = list(string)
  default     = []
}

variable "enable_api_gateway_execution_logging" {
  description = "Enable API Gateway execution logging"
  type        = bool
}

variable "enable_api_gateway_execution_request_tracing" {
  description = "Enable API Gateway execution request tracing"
  type        = bool
}

variable "cloudwatch_log_retention" {
  description = "The retention period for CloudWatch logs"
  type        = number
}

variable "logging_endpoint_arns" {
  description = "The ARNs of the logging endpoints"
  type        = list(string)
}

variable "cloudwatch_encryption_key_arn" {
  description = "The ARN of the CloudWatch encryption key"
  type        = string
}

variable "access_logging_template" {
  description = "The access logging template"
  type        = string
}

variable "waf_arns" {
  description = "The ARNs of any WAFs to attach to the API Gateway"
  type        = list(string)
  default     = []
}
