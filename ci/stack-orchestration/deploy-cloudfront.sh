#!/usr/bin/env bash
# shellcheck disable=SC2086
set -euo pipefail

#Ensure we are in the same dir as the script
cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 || exit

CLOUDFRONT_DISTRIBUTION_STACK_VERSION="v2.3.9"
CERTIFICATE_STACK_VERSION="v1.1.4"
CLOUDFRONT_MONITORING_STACK_VERSION="v2.1.0"

PROVISION_CLOUDFRONT_TLS_CERT=false
PROVISION_CLOUDFRONT=false
PROVISION_CLOUDFRONT_MONITORING=false
PROVISION_CLOUDFRONT_NOTIFICATION_STACK=false

PROVISION_COMMAND="../../../devplatform-deploy/stack-orchestration-tool/provisioner.sh"

export AWS_PAGER=
export SKIP_AWS_AUTHENTICATION="${SKIP_AWS_AUTHENTICATION:-true}"
export AUTO_APPLY_CHANGESET="${AUTO_APPLY_CHANGESET:-false}"

if [ ! -f ${PROVISION_COMMAND} ]; then
  echo "Provisioner script not found. Please clone dev-platform deploy repo next to this one."
  exit 1
fi

function usage {
  cat << USAGE
  Script to deploy the OIDC CloudFront distribution and manage the migration from the auth account cloudfront to the orchestration account.

  Usage:
    $0 [-e|--environment <env name>] [-c|--certificate] [-d|--distribution] [-m|--monitoring]

  Options:
    -e, --environment        The environment you wish to deploy to i.e dev, build, staging, integration, or production
    -c, --certificate        Creates certificate in us-east-1 region for CloudFront Distribution.
    -d, --distribution       Creates the CloudFront distribution
    -m, --monitoring         Deploys CloudFront Extended Monitoring stack in us-east-1
    -n, --notification        Deploys a stack which allows us to forward our Cloudfront alarms to Slack in our non-prod envs, or PagerDuty in
                             the production environment. This requires us to setup some manual secrets for the relevant webhooks/slack channel IDs.
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
    -c | --certificate)
      PROVISION_CLOUDFRONT_TLS_CERT=true
      ;;
    -d | --distribution)
      PROVISION_CLOUDFRONT=true
      ;;
    -m | --monitoring)
      PROVISION_CLOUDFRONT_MONITORING=true
      ;;
    -n | --notification)
      PROVISION_CLOUDFRONT_NOTIFICATION_STACK=true
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
done

TAGS_FILE="$(pwd)/configuration/${ENVIRONMENT}/tags.json"
export TAGS_FILE

function provision_cloudfront_distribution() {
  export AWS_REGION="eu-west-2"
  echo "Provisioning cloudfront stack"

  STACK_TAGS_FILE="$(pwd)/configuration/${ENVIRONMENT}/${ENVIRONMENT}-oidc-cloudfront/tags.json"
  # shellcheck disable=SC2155
  local params_file="$(pwd)/configuration/${ENVIRONMENT}/${ENVIRONMENT}-oidc-cloudfront/parameters.json"

  if [ -f "${STACK_TAGS_FILE}" ]; then
    tmp_tags_file="$(mktemp)"
    jq -s 'add | group_by(.Key) | map(last)' "${TAGS_FILE}" "${STACK_TAGS_FILE}" > "${tmp_tags_file}"
  fi
  TAGS_FILE="${tmp_tags_file}" PARAMETERS_FILE="${params_file}" ${PROVISION_COMMAND} "${ENVIRONMENT}" "${ENVIRONMENT}-oidc-cloudfront" "cloudfront-distribution" "${CLOUDFRONT_DISTRIBUTION_STACK_VERSION}"

  echo "Provisioned cloudfront stack"
}

function provision_cloudfront_monitoring() {

  echo "Provisioning cloudfront monitoring stack"
  AWS_REGION="us-east-1" PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/cloudfront-monitoring-alarm/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "${ENVIRONMENT}-oidc-cloudfront-monitoring" "cloudfront-monitoring-alarm" "${CLOUDFRONT_MONITORING_STACK_VERSION}"

  echo "Provisioned cloudwatch alarm stack"
}

function provision_cloudfront_certificate() {

  echo "Provisioning cloudfront certificate stack"
  AWS_REGION="us-east-1" PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/cloudfront-tls-certificate/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "cloudfront-tls-certificate" "certificate" "${CERTIFICATE_STACK_VERSION}"

  echo "Provisioned cloudfront certificate stack"
}

function provision_cloudfront_notification() {
  echo "Provisioning cloudfront notification stack"

  # shellcheck disable=SC2155
  local parameters=$(jq -r '.[] | "\(.ParameterKey)=\(.ParameterValue)"' "configuration/${ENVIRONMENT}/cloudfront-notifications/parameters.json")

  # shellcheck disable=SC2155
  local tags=$(jq -r '.[] | "\(.Key)=\(.Value)" | gsub(" ";"-")' "configuration/${ENVIRONMENT}/tags.json")

  # shellcheck disable=SC2155
  local template_dir="$(pwd)/manual-stacks/cloudfront-notifications/template.yaml"

  if [ ! -f "${template_dir}" ]; then
    echo "Could not find the manual cloudfront notification template stack at path: ${template_dir}"
    exit 1
  fi

  # We need to potentially build the lambda
  pushd "$(pwd)/manual-stacks/cloudfront-notifications"

  sam build
  sam deploy \
    --stack-name "cloudfront-notification" \
    --resolve-s3 true \
    --s3-prefix "cloudfront-notification" \
    --region "us-east-1" \
    --capabilities "CAPABILITY_IAM" \
    --confirm-changeset \
    --no-fail-on-empty-changeset \
    --parameter-overrides ${parameters} \
    --tags ${tags}

  popd

  echo "Provisioned cloudfront notification stack"

}

# deploy certs first as these are a dependency of the cloudfront stack
[ "${PROVISION_CLOUDFRONT_TLS_CERT}" == "true" ] && provision_cloudfront_certificate

# deploy CF distribution
[ "${PROVISION_CLOUDFRONT}" == "true" ] && provision_cloudfront_distribution

#Deploy notification stack as it is needed by the monitoring stack.

[ "${PROVISION_CLOUDFRONT_NOTIFICATION_STACK}" == "true" ] && provision_cloudfront_notification

# deploy monitoring as it needs the CF distribution to exist
[ "${PROVISION_CLOUDFRONT_MONITORING}" == "true" ] && provision_cloudfront_monitoring

#Reset stuff
export AWS_REGION="eu-west-2"
