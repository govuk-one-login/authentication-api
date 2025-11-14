#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

API_NAME="${1?Usage: $0 <api-name> <environment> [local-port:-8123]}"
ENVIRONMENT="${2?Usage: $0 <api-name> <environment> [local-port:-8123]}"
PORT=${3:-8123}

PROXY_SCRIPT=
case "${API_NAME}" in
  "account-management")
    PROXY_SCRIPT="${DIR}/../ci/terraform/account-management/api-proxy.sh"
    ;;
  *)
    echo "Invalid API name: ${API_NAME}. Valid APIs are: account-management"
    exit 1
    ;;
esac

case "${ENVIRONMENT}" in
  authdev* | dev)
    export AWS_PROFILE="di-auth-development-admin"
    ;;
  *)
    echo "Invalid environment: ${ENVIRONMENT}. Valid environments are: authdev1, authdev2, dev"
    exit 1
    ;;
esac

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

"${PROXY_SCRIPT}" "${ENVIRONMENT}" "${PORT}"
