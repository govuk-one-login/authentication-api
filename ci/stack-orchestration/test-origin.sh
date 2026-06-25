#!/usr/bin/env bash
set -euo pipefail

function usage() {
  cat << USAGE
  Script to test the "origin." domain integration with the API Gateway.

  Usage:
    ex: ./test-origin.sh -e dev

  Options:
    -e, --environment   The environment you wish to test the origin for.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "${1}" in
    -e | --environment)
      ENVIRONMENT="${2}"

      PERMITTED_ENVIRONMENTS="dev build staging integration production"
      if ! [[ ${PERMITTED_ENVIRONMENTS} =~ ( |^)${ENVIRONMENT}( |$) ]]; then
        echo "Environment provided: ${ENVIRONMENT} is not one of ${PERMITTED_ENVIRONMENTS}"
        exit 1
      fi

      echo "Selected environment: ${ENVIRONMENT}"
      shift
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
done

function curl_origin_with_header() {
  local expected_managed_secret_name="${ENVIRONMENT}-oidc-cloudfront-origin-cloaking-header-managed"
  local secret_value=""
  secret_value=$(aws secretsmanager get-secret-value --secret-id "${expected_managed_secret_name}" | jq -r ".SecretString" || exit 1)

  if [ -z "${secret_value}" ]; then
    echo "Failed to get origin cloaking secret"
    exit 1
  fi

  local expected_origin_domain="origin.oidc.${ENVIRONMENT}.account.gov.uk"
  local expected_fqdn="oidc.${ENVIRONMENT}.account.gov.uk"

  if [[ ${ENVIRONMENT} == "production" ]]; then
    expected_origin_domain="origin.oidc.account.gov.uk"
    expected_fqdn="oidc.account.gov.uk"
  fi

  # needs -k flag
  curl -H "origin-cloaking-secret: ${secret_value}" -H "Host: ${expected_fqdn}" -k "https://${expected_origin_domain}/trustmark"
}

curl_origin_with_header
