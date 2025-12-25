#!/bin/bash
set -euo pipefail
# Script to connect to an api proxy instance

ENVIRONMENT="${1?Usage: $0 <environment> [local-port:-8123]}"
PORT=${2:-8123}

export AWS_PROFILE=di-authentication-development-AdministratorAccessPermission

echo "Ensuring AWS CLI is configured ..."
# Test if the AWS CLI is configured with the correct profile
if ! sso_session="$(aws configure get sso_session --profile "${AWS_PROFILE}")"; then
  echo "AWS CLI profile ${AWS_PROFILE} is not configured."
  echo "Please visit https://govukverify.atlassian.net/wiki/x/IgFm5 for instructions."
  exit 1
fi
if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" > /dev/null; then
  aws sso login --sso-session "${sso_session}"
fi

echo "Fetching the instance ID from AWS..."
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=${ENVIRONMENT}-mm-api-developer-proxy-new" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)

if [ -z "${INSTANCE_ID}" ] || [ "${INSTANCE_ID}" == "None" ]; then
  echo "No running instance found for ${ENVIRONMENT}-mm-api-developer-proxy"
  exit 1
fi

echo "Starting port forwarding from localhost:${PORT} to ${ENVIRONMENT} Method Management API proxy..."
if ! aws ssm start-session \
  --target "${INSTANCE_ID}" \
  --document-name "${ENVIRONMENT}-mm-api-developer-proxy-ssm-document" \
  --parameters "{\"localPortNumber\":[\"${PORT}\"]}"; then

  # shellcheck disable=SC2016
  echo 'If the session failed to start, try installing the AWS CLI Session manager plugin: `brew install session-manager-plugin`.'
  exit 1
fi

# Usage instructions:
# ./api-proxy.sh <environment> [local-port]
# Default local port is 8123 if not specified
