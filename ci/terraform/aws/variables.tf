variable "lambda_zip_file" {
  default     = "../../../serverless/lambda/build/distributions/lambda.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "notify_api_key" {
  description = "The API key required to communicate with Notify"
  type        = string
}

variable "environment" {
  type    = string
  default = "test"
}

variable "api_deployment_stage_name" {
  type    = string
  default = "test"
}

variable "api_base_url" {
  type    = string
  default = "http://localhost:8080"
}