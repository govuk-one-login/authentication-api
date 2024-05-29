terraform {
  required_version = ">= 1.7.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.44.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.11.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.2"
    }
  }
}
