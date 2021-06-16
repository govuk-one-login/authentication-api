variable "name" {
  type    = string
}

variable "environment" {
  type    = string
}

variable "sender_principal_arns" {
  type = list(string)
}

variable "handler_runtime" {
  type    = string
  default = "java11"
}

variable "handler_environment_variables" {
  type = map(string)
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

variable "lambda_zip_file" {
  type = string
}

variable "handler_function_name" {
  type = string
}

variable "security_group_id" {
  type = string
  description = "The id of the security for the lambda"
}

variable "subnet_id" {
  type = list(string)
  description = "The id of the subnets for the lambda"
}
