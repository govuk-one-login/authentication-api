terraform {
  required_version = ">= 1.7.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.44.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "= 0.10.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.6.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "= 2.5.1"
    }
  }
}
