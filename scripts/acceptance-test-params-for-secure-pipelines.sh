#!/usr/bin/env bash
set -euo pipefail

pushd "$(git rev-parse --show-toplevel)" > /dev/null || exit 1

# This script is used to generate commands to replicate SSM parameters for secure pipelines accounts

test -n "${AWS_PROFILE:-}" || (echo "ERROR: AWS_PROFILE is not set" && exit 1)

ENVIRONMENT="${1?Usage: $0 <environment> [<new_environment>]}"
NEW_ENVIRONMENT="${2:-some-new-environment-name}"

# params=($(find ci/terraform -type f -name "acceptance-test-values.tf" | xargs -L1 grep '/acceptance-tests' | grep -v id | awk '{ print $3 }' | tr -d '"' | sort -u))

mapfile -t params < <(find ci/terraform -type f -name "acceptance-test-values.tf" -print0 | xargs -0 -L1 grep '/acceptance-tests' | grep -v id | awk '{ print $3 }' | tr -d '"' | sort -u)

for param in "${params[@]}"; do
  existing_param_name="${param/\$\{var.environment\}/${ENVIRONMENT}}"
  new_param_name="${param/\$\{var.environment\}/${NEW_ENVIRONMENT}}"
  value=$(aws ssm get-parameter --name "${existing_param_name}" | jq -r .Parameter.Value)
  echo "aws ssm put-parameter --name ${new_param_name} --value \"${value}\" --type String --overwrite"
done
