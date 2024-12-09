/**
 * # Is This The Primary Environment?
 *
 * This module is used to determine if the environment is the primary environment in the current account:region.
 * The primary environments are defined in the `primary_environment_names` local variable.
 * The module will output a boolean value indicating if the environment is a primary environment.
 *
 * ## Why this module?
 *
 * This module is intended to standardize the way we determine if an environment is a primary environment, to ensure consistency across the codebase.
 * Some resources are only deployed to the primary environment, and this module can be used to conditionally deploy those resources without recreating the check everywhere,
 * which could lead to inconsistencies.
 */

variable "environment" {
  type        = string
  description = "The name of the environment"
}

locals {
  primary_environment_names = ["production", "staging", "dev", "build"]
}

output "is_primary_environment" {
  value       = contains(local.primary_environment_names, var.environment)
  description = "True if this environment is the primary environment in this account:region else false"
}
