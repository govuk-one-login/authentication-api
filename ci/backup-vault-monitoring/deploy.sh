#!/usr/bin/env bash
set -euo pipefail

export AWS_PAGER=""

function loginAws() {
  export AWS_REGION=eu-west-2
  case $1 in
    integration)
      export AWS_PROFILE=di-orchestration-integration-admin
      ;;
    production)
      export AWS_PROFILE=di-orchestration-admin
      ;;
  esac

  # shellcheck disable=SC1091
  source "../../scripts/export_aws_creds.sh"
}

PERMITTED_ENVIRONMENTS="integration production"

if [[ $# == 0 ]] || ! [[ ${PERMITTED_ENVIRONMENTS} =~ ( |^)$1( |$) ]]; then
  echo "Call ./deploy <env>, where <env> is one of ${PERMITTED_ENVIRONMENTS}"
  exit 1
fi

ENVIRONMENT=$1

PARAMETERS_FILE=${PARAMETERS_FILE:=./${ENVIRONMENT}/parameters.json}
TAGS_FILE=${TAGS_FILE:=./${ENVIRONMENT}/tags.json}

if [ ! -f "${PARAMETERS_FILE}" ]; then
  echo "Configuration file not found. Please see README.md"
  exit 1
fi

if [ ! -f "${TAGS_FILE}" ]; then
  echo "Tags file not found. Please see README.md"
  exit 1
fi

loginAws "${ENVIRONMENT}"

TEMPLATE_URL="https://backup-template-storage-templatebucket-747f3bzunrod.s3.eu-west-2.amazonaws.com/backup-vault-monitoring/template.yaml"

if [[ $# == 2 ]] && [[ $2 == "--create" ]]; then
  aws cloudformation create-stack \
    --region eu-west-2 \
    --enable-termination-protection \
    --stack-name="${ENVIRONMENT}-backup-vault-monitoring" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --template-url ${TEMPLATE_URL} \
    --parameters="$(jq '. | tojson' -r "${PARAMETERS_FILE}")" \
    --tags="$(jq '. | tojson' -r "${TAGS_FILE}")"
else
  aws cloudformation update-stack \
    --region eu-west-2 \
    --stack-name="${ENVIRONMENT}-backup-vault-monitoring" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --template-url ${TEMPLATE_URL} \
    --parameters="$(jq '. | tojson' -r "${PARAMETERS_FILE}")" \
    --tags="$(jq '. | tojson' -r "${TAGS_FILE}")"
fi
