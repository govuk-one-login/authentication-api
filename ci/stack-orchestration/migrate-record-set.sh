#!/bin/bash
set -euo pipefail

# Ensure we are in the directory of the script
cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 || exit

EXPORT_RECORDS=false
IMPORT_RECORDS=false

RECORDS_BATCH_CHANGES_SUFFIX="migrated-records"

function usage() {
  cat << USAGE
  Script to lower the ttl of NS records in a specified hosted zone

  Usage:
    $0 [-z|--zone-id] <ZONE-ID> [-e|--environment] --import OR --export
    ex: ./migrate-record-set.sh -z Z148QEXAMPLE8V --export -e dev

  Options:
    -z, --zone-id         The zone ID of the Hosted Zone in which you would like run the current operation on.
    -e, --environment     The environment which you are running the script against. This is mainly used in the
                          filename for the recordset.
    --import              Imports the records stored at <ENVIRONMENT>-migrated-records.json to the specified hosted zone
    --export              Exports the records from the specified hosted zone to a file called <ENVIRONMENT>-migrated-records.json
USAGE
}

if [ $# -lt 3 ]; then
  usage
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "${1}" in
    -z | --zone-id)
      HOSTED_ZONE_ID="${2}"
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
    --import)
      IMPORT_RECORDS=true
      ;;
    --export)
      EXPORT_RECORDS=true
      ;;
    *)
      echo "Bad argument: ${1}"
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ ${IMPORT_RECORDS} == "true" ]] && [[ ${EXPORT_RECORDS} == "true" ]]; then
  echo "Cannot both import and export a records set in one action!"
  exit 1
fi

function export_record_set() {
  # SOA and NS records should not be copied over as they are specific to the hosted zone
  # We're gonna manage the A records in Cloudformation
  local records_excluding_ns_soa_and_a=""
  records_excluding_ns_soa_and_a=$(aws route53 list-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --query "ResourceRecordSets[? (Type != 'NS' && Type != 'SOA' && Type != 'A')]" \
    --output json) || exit 1

  # shellcheck disable=SC2128
  if [ -z "${records_excluding_ns_soa_and_a}" ] || [ "${records_excluding_ns_soa_and_a}" == "[]" ]; then
    echo "Error: Could not record set for hosted zone ID: ${HOSTED_ZONE_ID}."
    exit 1
  fi

  jq '{
      Comment: "Importing records from old hosted zone",
      Changes: [
           {
            Action: "CREATE",
            ResourceRecordSet: .[]  | select(.Type != "SOA" and .Type != "NS" and .Type != "A")
          }
      ]
    }' <<< "${records_excluding_ns_soa_and_a}" > "$(pwd)/${ENVIRONMENT}-${RECORDS_BATCH_CHANGES_SUFFIX}.json"
}

function import_record_set() {
  local batch_records_file=""
  batch_records_file="$(pwd)/${ENVIRONMENT}-${RECORDS_BATCH_CHANGES_SUFFIX}.json"

  local change_id=""
  change_id=$(aws route53 change-resource-record-sets \
    --hosted-zone-id "${HOSTED_ZONE_ID}" \
    --change-batch "file://${batch_records_file}" \
    --query "ChangeInfo.Id" \
    --output text) || exit 1

  echo "Change submitted (ID: ${change_id}). Wait for propagation..."
}

[ "${EXPORT_RECORDS}" == "true" ] && export_record_set && exit 0

[ "${IMPORT_RECORDS}" == "true" ] && import_record_set && exit 0
