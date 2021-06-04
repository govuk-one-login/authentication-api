variable "lambda-zip-file" {
  type        = string
}

variable "rest_api_id" {
  type = string
}

variable "root_resource_id" {
  type = string
}

variable "execution_arn" {
  type = string
}

variable "environment" {
  type = string
  default = "test"
}

variable "api-deployment-stage-name" {
  type = string
  default = "test"
}