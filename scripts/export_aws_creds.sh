#!/bin/bash
set -euo pipefail

[[ "${BASH_SOURCE[0]}" != "${0}" ]] || {
  echo "Error: Script must be sourced, not executed"
  exit 1
}

if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  echo "Using AWS credentials from existing environment variables"
else
  echo "Exporting credentials from AWS CLI profile ${AWS_PROFILE}"

  # Test if the AWS CLI is configured with the correct profile
  if ! sso_session="$(aws configure get sso_session --profile "${AWS_PROFILE}")"; then
    echo "AWS CLI profile ${AWS_PROFILE} is not configured."
    echo "Please visit https://govukverify.atlassian.net/wiki/x/IgFm5 for instructions."
    exit 1
  fi
  if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" >/dev/null; then
    aws sso login --sso-session "${sso_session}"
  fi
  if ! aws_export="$(aws configure export-credentials --profile "${AWS_PROFILE}" --format env 2>/dev/null)"; then
    echo "Failed to export AWS credentials from AWS CLI profile ${AWS_PROFILE}."
    echo "Please visit https://govukverify.atlassian.net/wiki/x/IgFm5 for instructions."
    exit 1
  fi
  eval "${aws_export}"
fi

configured_region="$(aws configure get region --profile "${AWS_PROFILE}" 2>/dev/null)"
if [[ -n "${configured_region:-}" ]]; then
  export AWS_REGION="${configured_region}"
fi
