terraform {
  required_version = ">= 1.9.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.75.1"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.12.1"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.3"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.5.2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.6"
    }
  }
}
