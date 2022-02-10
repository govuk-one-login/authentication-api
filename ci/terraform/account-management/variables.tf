variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "notify_api_key" {
  description = "The API key required to communicate with Notify"
  type        = string
}

variable "notify_url" {
  type    = string
  default = null
}

variable "notify_template_map" {
  type = map(string)
  default = {
    VERIFY_EMAIL_TEMPLATE_ID         = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    VERIFY_PHONE_NUMBER_TEMPLATE_ID  = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    EMAIL_UPDATED_TEMPLATE_ID        = "0a200a63-97b2-4920-bc40-48e9a9e1121e"
    DELETE_ACCOUNT_TEMPLATE_ID       = "0706adcc-b593-4d2d-afa6-c3da7149e426"
    PHONE_NUMBER_UPDATED_TEMPLATE_ID = "8274a2a3-5121-4630-a27e-e8578f8cba59"
    PASSWORD_UPDATED_TEMPLATE_ID     = "323ebef4-cfa7-414f-bfba-1db324acdd66"
  }
}

variable "environment" {
  type = string
}

variable "aws_region" {
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

variable "aws_dynamodb_endpoint" {
  type    = string
  default = null
}

variable "lambda_dynamo_endpoint" {
  type        = string
  default     = "http://dynamodb:8000"
  description = "The endpoint that the Lambda must use to connect to DynamoDB API. This may or may not be the same as aws_dynamodb_endpoint"
}

variable "dns_state_bucket" {
  type = string
}

variable "dns_state_key" {
  type = string
}

variable "dns_state_role" {
  type = string
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
}

variable "lambda_zip_file" {
  default     = "../../../account-management-api/build/distributions/account-management-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
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

variable "external_redis_host" {
  type    = string
  default = "redis"
}

variable "external_redis_port" {
  type    = number
  default = 6379
}

variable "external_redis_password" {
  type    = string
  default = null
}

variable "redis_use_tls" {
  type    = string
  default = "true"
}

variable "redis_node_size" {
  default = "cache.t2.small"
}

variable "keep_lambdas_warm" {
  default = true
  type    = bool
}

variable "lambda_warmer_zip_file" {
  default     = "../../../lambda-warmer/build/distributions/lambda-warmer.zip"
  description = "Location of the Lambda Warmer ZIP file"
  type        = string
}

variable "common_state_bucket" {
  type = string
}

variable "cloudwatch_log_retention" {
  default     = 1
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "dlq_alarm_threshold" {
  default     = 1
  type        = number
  description = "The number of messages on a DLQ before a Cloudwatch alarm is generated"
}

variable "waf_alarm_blocked_reqeuest_threshold" {
  default     = 1000
  type        = number
  description = "The number of blocked requests caught by the WAF before a Cloudwatch alarm is generated"
}

variable "lambda_min_concurrency" {
  default     = 10
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "customer_support_link_route" {
  type    = string
  default = "support"
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:45678/"
}
