variable "environment" {
  type = string
}

variable "extra_tags" {
  default     = {}
  type        = map(string)
  description = "Extra tags to apply to resources"
}

variable "txma_account_id" {
  type        = string
  description = "Account id of the corresponding TxMA processor"
}

variable "service_name" {
  type        = string
  description = "Name of the service that will be using these queues. Used for disambiguation"
}

locals {
  extra_tags = merge(var.extra_tags, {
    ServiceName = var.service_name
  })
}
