variable "queue_name" {
  type    = string
}

variable "environment" {
  type    = string
}

variable "principals_arns" {
  type = list(string)
}