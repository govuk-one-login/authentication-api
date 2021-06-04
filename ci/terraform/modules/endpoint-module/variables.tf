variable "endpoint-name" {
  type = string
}

variable "endpoint-method" {
  type = string
}

variable "lambda-zip-file" {
  type = string
}

variable "handler-function-name" {
  type = string
}

variable "handler-environment-variables" {
  type = map(string)
}

variable "handler-runtime" {
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

variable "api-deployment-stage-name" {
  type    = string
  default = "test"
}

variable "lambda-iam-policy" {
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