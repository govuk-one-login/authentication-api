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