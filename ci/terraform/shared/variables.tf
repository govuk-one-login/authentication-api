variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
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

variable "lambda_dynamo_endpoint" {
  type        = string
  default     = "http://dynamodb:8000"
  description = "The endpoint that the Lambda must use to connect to DynamoDB API. This may or may not be the same as aws_dynamodb_endpoint"
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "external_redis_host" {
  type    = string
  default = "redis"
}

variable "terms_and_conditions" {
  type    = string
  default = "1.0"
}

variable "external_redis_port" {
  type    = number
  default = 6379
}

variable "external_redis_password" {
  type    = string
  default = null
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:45678/"
}

variable "redis_use_tls" {
  type    = string
  default = "true"
}

variable "service_domain_name" {
  default = "auth.ida.digital.cabinet-office.gov.uk"
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
}

variable "logging_endpoint_enabled" {
  type        = bool
  default     = false
  description = "Whether the service should ship its Lambda logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
}

variable "stub_rp_clients" {
  default     = []
  type        = list(object({ client_name : string, callback_urls : list(string), logout_urls : list(string) }))
  description = "The details of RP clients to provision in the Client table"
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "keep_lambdas_warm" {
  default = true
  type    = bool
}

variable "redis_node_size" {
  default = "cache.t2.small"
}

variable "provision_dynamo" {
  type    = bool
  default = false
}

variable "dynamo_default_read_capacity" {
  type    = number
  default = 20
}

variable "dynamo_default_write_capacity" {
  type    = number
  default = 20
}
