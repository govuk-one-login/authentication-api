#!/bin/bash

if [[ -z ${CODEBUILD_BUILD_ID:-} ]]; then
  echo 'This should only be run in codebuild'
  exit 1
fi

_secrets_environment="${1}"

_tfvars_path="./terraform.tfvars.json"
if ! python3 "secrets-to-tfvars.py" "${_secrets_environment}" "${_tfvars_path}"; then
  echo "Failed to generate terraform.tfvars.json"
  exit 1
fi

_secret_count=$(jq '. | length' "${_tfvars_path}")
echo "Successfully retrieved ${_secret_count} secrets from AWS Secrets Manager and saved to ${_tfvars_path}"
