#!/usr/bin/env bash
set -euo pipefail

PREFIX="/deploy/api-migration"
GET_PARAMS=false
SET_PARAMS=false

function usage() {
  cat << USAGE
  Script to get/set the necessary SSM params for the API Gateway/Cloudfront migration

  Usage:
    ex: ./get-set-ssm-params.sh -e dev -d <DISTRIBUTION-ID> --get

  Options:
    -e, --environment   The environment to get/set SSM params in
    -d, --distribution-id The old cloudfront distribution ID to fetch the ssm parameter
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
    -d | --distribution-id)
      OLD_CLOUDFRONT_DISTRIBUTION_ID="${2}"
      shift
      ;;
    --get)
      GET_PARAMS=true
      ;;
    --set)
      SET_PARAMS=true
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ ${GET_PARAMS} == "true" ]] && [[ ${SET_PARAMS} == "true" ]]; then
  echo "Cannot both get and set params in one action!"
  exit 1
fi

function get_ssm_params() {

  local expected_api_custom_domain="oidc.${ENVIRONMENT}.account.gov.uk"

  if [[ ${ENVIRONMENT} == "production" ]]; then
    expected_api_custom_domain="oidc.account.gov.uk"
  fi

  local get_domains_response=""
  get_domains_response=$(aws apigateway get-domain-names --query "items[? (domainName == '${expected_api_custom_domain}')]") || exit 1

  # shellcheck disable=SC2128
  if [ -z "${get_domains_response}" ] || [ "${get_domains_response}" == "[]" ]; then
    echo "Error: Could not record set for hosted zone ID: ${HOSTED_ZONE_ID}."
    exit 1
  fi

  local regional_hosted_zone_id=""
  regional_hosted_zone_id=$(jq -r ".[].regionalHostedZoneId" <<< "${get_domains_response}") || exit 1

  local regional_domain_name=""
  regional_domain_name=$(jq -r ".[].regionalDomainName" <<< "${get_domains_response}") || exit 1

  local cloudfront_distribution_domain=""
  cloudfront_distribution_domain=$(aws cloudfront list-distributions --query "DistributionList.Items[? (Id == '${OLD_CLOUDFRONT_DISTRIBUTION_ID}')].DomainName" --output text) || exit 1

  local output="${PREFIX}/old-api-gateway-regional-hosted-zone-id=${regional_hosted_zone_id}\n${PREFIX}/old-api-gateway-regional-domain-name=${regional_domain_name}\n${PREFIX}/old-cloudfront-distribution-domain=${cloudfront_distribution_domain}"

  echo -e "${output}" >> "${ENVIRONMENT}-migration-ssm-params"
}

function put_ssm_parameters() {
  while IFS='=' read -r name val; do
    echo "Putting SSM param: ${name} with value: ${val}"
    # shellcheck disable=SC2086
    aws ssm put-parameter --name ${name} --value ${val} --type "String" || exit 1
  done < "${ENVIRONMENT}-migration-ssm-params"
}

[ "${GET_PARAMS}" == "true" ] && get_ssm_params && exit 0

[ "${SET_PARAMS}" == "true" ] && put_ssm_parameters && exit 0
