terraform {
  required_version = ">= 1.9.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.75.1"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.12.1"
    }
  }
}
