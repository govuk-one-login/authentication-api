#!/usr/bin/env bash
set -euo pipefail

NEW_TTL_VALUE=300

function usage() {
  cat << USAGE
  Script to lower the ttl of NS records in a specified hosted zone

  Usage:
    $0 [-z|--zone-id] <ZONE-ID> [-t|--ttl] <TTL>
    ex: ./update-ns-records-ttl.sh -z Z148QEXAMPLE8V -ttl 900 -e dev

  Options:
    -z, --zone-id         The zone ID of the Hosted Zone in which you would like to lower the TTL of NS records
    -e, --environment     The environment you are lowering the TTL for.
    -t, --ttl             The TTL you would like to set for the NS records. Default is 300 seconds (5 minutes)
USAGE
}

if [ $# -lt 2 ]; then
  usage
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "${1}" in
    -z | --zone-id)
      HOSTED_ZONE_ID="${2}"
      shift
      ;;
    -t | --ttl)
      if ! [[ ${2} =~ ^[0-9]+$ ]] || [[ ${2} -lt 300 ]] || [[ ${2} -gt 172800 ]]; then
        echo "TTL must be at least 300 seconds and less than 172800 (2 days). You provided: ${1}"
        exit 1
      fi
      NEW_TTL_VALUE=${2}
      shift
      ;;
    -e | --environment)
      ENVIRONMENT="${2}"

      PERMITTED_ENVIRONMENTS="dev build staging integration production"
      if ! [[ ${PERMITTED_ENVIRONMENTS} =~ ( |^)${ENVIRONMENT}( |$) ]]; then
        echo "Environment provided: ${ENVIRONMENT} is not one of ${PERMITTED_ENVIRONMENTS}"
        exit 1
      fi
      shift
      ;;
    *)
      echo "Bad argument: ${1}"
      usage
      exit 1
      ;;
  esac
  shift
done

case "${ENVIRONMENT}" in
  "dev")
    DOMAIN_NAME="oidc.dev.account.gov.uk"
    ;;
  "build")
    DOMAIN_NAME="oidc.build.account.gov.uk"
    ;;
  "staging")
    DOMAIN_NAME="oidc.staging.account.gov.uk"
    ;;
  "integration")
    DOMAIN_NAME="oidc.integration.account.gov.uk"
    ;;
  "production")
    DOMAIN_NAME="oidc.account.gov.uk"
    ;;
  *)
    exit 1
    ;;
esac

function update_ns_ttl() {

  echo "Getting NS records for domain name: ${DOMAIN_NAME}"
  local ns_records_json=""
  # Route53 has a trailing '.' on the domain name when calling list-resource-records
  ns_records_json=$(aws route53 list-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --query "ResourceRecordSets[?Type == 'NS' && Name == '${DOMAIN_NAME}.']" \
    --output json)

  if [ -z "${ns_records_json}" ] || [ "${ns_records_json}" == "[]" ]; then
    echo "Error: Could not find an NS record for ${DOMAIN_NAME} in ${HOSTED_ZONE_ID}."
    exit 1
  fi

  echo "Formatting to change batch set"
  # shellcheck disable=SC2155
  local resource_records=$(echo "${ns_records_json}" | jq -r '.[0].ResourceRecords')

  # See https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-migrating.html#hosted-zones-migrating-prepare
  #The trailing '.' here is fine as route53 treats the "Name":wwww.example.com. equivalent to Name:wwww.example.com
  # See: https://docs.aws.amazon.com/Route53/latest/APIReference/API_ResourceRecordSet.html#:~:text=This%20means%20that%20Route%2053%20treats%20www.example.com%20(without%20a%20trailing%20dot)%20and%20www.example.com.%20(with%20a%20trailing%20dot)%20as%20identical.

  local change_batch="{
      \"Comment\": \"Updating NS record TTL\",
      \"Changes\": [
          {
              \"Action\": \"UPSERT\",
              \"ResourceRecordSet\": {
                  \"Name\": \"${DOMAIN_NAME}.\",
                  \"Type\": \"NS\",
                  \"TTL\": ${NEW_TTL_VALUE},
                  \"ResourceRecords\": ${resource_records}
              }
          }
      ]
  }
  "

  # shellcheck disable=SC2155
  local new_resource_records=$(echo "${change_batch}" | jq ".Changes[0].ResourceRecordSet")

  echo "Diff of changes:
  "
  # needs || true as diff returns non-zero exit code when a difference is present
  diff -ys <(echo "${ns_records_json}" | jq --sort-keys '.[0]') <(echo "${new_resource_records}" | jq --sort-keys .) || true

  while true; do
    read -rp "Happy with the diff? (yY/nN): " yn
    case ${yn} in
      [Yy]*)
        echo "Proceeding..."
        break
        ;;
      [Nn]*)
        echo "Exiting..."
        exit 0
        ;;
      *)
        echo "Please answer yes or no."
        ;;
    esac
  done

  echo "Submitting update request to Route 53..."
  local change_id=""
  change_id=$(aws route53 change-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --change-batch "${change_batch}" \
    --query "ChangeInfo.Id" \
    --output text)

  echo "Change submitted (ID: ${change_id}). Wait for propagation..."
}

update_ns_ttl
