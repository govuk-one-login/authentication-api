variable "lambda_zip_file" {
  default     = "../../../serverless/lambda/build/distributions/lambda.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "environment" {
  type    = string
  default = "local"
}

variable "api_deployment_stage_name" {
  type    = string
  default = "local"
}

variable "api_base_url" {
  type    = string
  default = "http://localhost:8080"
}

variable "localstack_endpoint" {
  type = string
  default = "http://localhost:45678"
}

variable "notify_url" {
  type = string
}

variable "notify_api_key" {
  type = string
}