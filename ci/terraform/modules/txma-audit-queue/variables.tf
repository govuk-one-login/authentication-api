variable "environment" {
  type = string
}

variable "default_tags" {
  default     = {}
  type        = map(string)
  description = "Default tags to apply to all resources"
}

variable "txma_account_id" {
  type        = string
  description = "Account id of the corresponding TxMA processor"
}

variable "service_name" {
  type        = string
  description = "Name of the service that will be using these queues. Used for disambiguation"
}