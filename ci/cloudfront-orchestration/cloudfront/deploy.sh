#!/usr/bin/env bash
set -euo pipefail

export AWS_PAGER=""

function loginAws() {
  export AWS_REGION=eu-west-2
  case $1 in
    dev)
      export AWS_PROFILE=gds-di-development-admin
      ;;
    build)
      export AWS_PROFILE=gds-di-development-admin
      ;;
    staging)
      export AWS_PROFILE=di-auth-staging-admin
      ;;
    integration)
      export AWS_PROFILE=gds-di-development-admin
      ;;
    production)
      export AWS_PROFILE=gds-di-production-admin
      ;;
  esac

  # shellcheck disable=SC1091
  source "../../../scripts/export_aws_creds.sh"
}

function exportSecrets() {
  SECRET_ENVIRONMENT="$1"

  if [[ ${SECRET_ENVIRONMENT} == "dev" ]]; then
    SECRET_ENVIRONMENT=sandpit
  fi

  ENV=${ENVIRONMENT} # The read_secrets script messes with the value of ENVIRONMENT
  # shellcheck disable=SC1091
  source "../../../scripts/read_secrets__main.sh" "${SECRET_ENVIRONMENT}"
  ENVIRONMENT=${ENV}
}

PERMITTED_ENVIRONMENTS="dev build staging integration production"

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
exportSecrets "${ENVIRONMENT}"

if [[ -z ${ORIGIN_CLOAKING_HEADER:-} ]]; then
  if [[ -z ${TF_VAR_oidc_origin_cloaking_header:-} ]]; then
    echo "No value set for ORIGIN_CLOAKING_HEADER and no deployment secret set"
    exit 1
  fi
  ORIGIN_CLOAKING_HEADER="${TF_VAR_oidc_origin_cloaking_header}"
fi
if [[ -z ${PREVIOUS_ORIGIN_CLOAKING_HEADER:-} ]]; then
  if [[ -z ${TF_VAR_previous_oidc_origin_cloaking_header:-} ]]; then
    echo "No value set for PREVIOUS_ORIGIN_CLOAKING_HEADER and no deployment secret set"
    exit 1
  fi
  PREVIOUS_ORIGIN_CLOAKING_HEADER="${TF_VAR_previous_oidc_origin_cloaking_header}"
fi

TEMPLATE_URL="https://template-storage-templatebucket-1upzyw6v9cs42.s3.amazonaws.com/cloudfront-distribution/template.yaml"

PARAMETERS=$(jq ". += [{\"ParameterKey\":\"OriginCloakingHeader\",\"ParameterValue\":\"${ORIGIN_CLOAKING_HEADER}\"},{\"ParameterKey\":\"PreviousOriginCloakingHeader\",\"ParameterValue\":\"${PREVIOUS_ORIGIN_CLOAKING_HEADER}\"}] | tojson" -r "${PARAMETERS_FILE}")

if [[ $# == 2 ]] && [[ $2 == "--create" ]]; then
  aws cloudformation create-stack \
    --region eu-west-2 \
    --enable-termination-protection \
    --stack-name="${ENVIRONMENT}-oidc-cloudfront" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --template-url ${TEMPLATE_URL} \
    --parameters="${PARAMETERS}" \
    --tags="$(jq '. | tojson' -r "${TAGS_FILE}")"
else
  aws cloudformation update-stack \
    --region eu-west-2 \
    --stack-name="${ENVIRONMENT}-oidc-cloudfront" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --template-url ${TEMPLATE_URL} \
    --parameters="${PARAMETERS}" \
    --tags="$(jq '. | tojson' -r "${TAGS_FILE}")"
fi
