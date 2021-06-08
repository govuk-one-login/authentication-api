variable "endpoint_name" {
  type = string
}

variable "endpoint_method" {
  type = string
}

variable "lambda_zip_file" {
  type = string
}

variable "handler_function_name" {
  type = string
}

variable "handler_environment_variables" {
  type = map(string)
}

variable "handler_runtime" {
  type    = string
  default = "java11"
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
  type    = string
  default = "test"
}

variable "api_deployment_stage_name" {
  type    = string
  default = "test"
}

variable "lambda_iam_policy" {
  type    = string
  default = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

variable "security_group_id" {
  type = string
  description = "The id of the security for the lambda"
}