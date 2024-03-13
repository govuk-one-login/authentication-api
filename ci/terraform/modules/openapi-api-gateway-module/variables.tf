variable "environment" {
  description = "The environment the API Gateway is being deployed for"
  type        = string
}
variable "openapi_spec" {
  description = "The OpenAPI specification to use for the API Gateway"
  type        = string
}

variable "resource_prefix" {
  description = "The prefix to use for created resources"
  type        = string
}

variable "short_resource_prefix" {
  description = "The short prefix to use for created resources"
  type        = string
  validation {
    condition     = length(var.short_resource_prefix) <= 4
    error_message = "The short resource prefix must be 3 characters or less"
  }
}

variable "default_tags" {
  description = "The default tags to apply to resources"
  type        = map(string)
}

variable "endpoint_modules" {
  description = "The modules to use for the API Gateway endpoints"
  type        = map(any)
}

variable "cloudwatch_log_retention" {
  description = "The number of days to retain the CloudWatch logs for"
  type        = number
}

variable "logging_endpoint_arns" {
  description = "The ARNs of the logging endpoints to send the API Gateway logs to"
  type        = list(string)
}

variable "cloudwatch_encryption_key_arn" {
  description = "The ARN of the KMS key to use for encrypting the CloudWatch logs"
  type        = string
}

variable "access_logging_template" {
  description = "The template to use for the access logging"
  type        = string
}

variable "enable_api_gateway_execution_logging" {
  description = "Whether to enable execution logging for the API Gateway"
  type        = bool
}

variable "enable_api_gateway_execution_request_tracing" {
  description = "Whether to enable request tracing for the API Gateway"
  type        = bool
}

variable "domain_name" {
  description = "The domain name to use for the API Gateway"
  type        = string
}

variable "waf_arn" {
  description = "The ARN of the WAF to associate with the API Gateway"
  type        = number
}
