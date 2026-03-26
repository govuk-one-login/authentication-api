#!/usr/bin/env bash
set -euo pipefail

#Ensure we are in the same dir as the script
cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 || exit

# To update a stack bump the version here and run the deployment command which contains that stack
VPC_STACK_VERSION="v2.10.0"
SECURE_PIPELINE_STACK_VERSION="v2.95.0"
GITHUB_IDENTITY_STACK_VERSION="v1.1.1"
SIGNER_STACK_VERSION="v1.0.8"
CLOUDWATCH_ALARM_STACK_VERSION="v0.0.10"
API_GATEWAY_LOGGING_STACK_VERSION="v1.0.9"

PROVISION_BASE_STACKS=false
PROVISION_VPC_STACK=false
PROVISION_PIPELINE_STACK=false
PROVISION_TXMA_STACK=false
PROVISION_CLOUDWATCH_ALARM_STACK=false

ENVIRONMENT=dev

TAGS_FILE="$(pwd)/configuration/${ENVIRONMENT}/tags.json"

# Use the dev-platform stack orchestration tool most of the time
PROVISION_COMMAND="../../../devplatform-deploy/stack-orchestration-tool/provisioner.sh"

#Modifed script for local use
LOCAL_PROVISION_COMMAND="./local-provisioner.sh"

if [ ! -f ${PROVISION_COMMAND} ]; then
  echo "Provisioner script not found. Please clone dev-platform deploy repo next to this one."
  exit 1
fi

if [ ! -f ${LOCAL_PROVISION_COMMAND} ]; then
  echo "Local provision command not found"
  exit 1
fi

export AWS_PAGER=
export SKIP_AWS_AUTHENTICATION="${SKIP_AWS_AUTHENTICATION:-true}"
export AUTO_APPLY_CHANGESET="${AUTO_APPLY_CHANGESET:-false}"
export TAGS_FILE

function usage() {
  cat << USAGE
  Script to bootstrap di-orchestration-dev account

  Usage:
    $0 [-b|--base-stacks][-p|--pipelines] [-v|--vpc] [-t|--txma]

  Options:
    -l, --list-base-stacks                 Lists the stacks which are deployed as part of the base stacks command
    -b, --base-stacks                      Provision base stacks
    -p, --pipelines                        Provision secure pipelines
    -v, --vpc                              Provision VPC stack
    -t, --txma                             Provision the manual TxMA stack for auditing.
    -c, --cloudwatch-alarm                 Provisions the cloudwatch alarm stack: A stack for deploying an alarm which
                                           monitors the lambda code storage and sends an alert when a threshold is reached.
                                           See confluence page: https://govukverify.atlassian.net/wiki/x/AwCc3Q
USAGE
}

function list_base_stacks() {
  cat << BASE_STACKS
  Base stacks for the dev account:
  - Github Identity Provider: A stack which allows Github actions to assume a role for uploading an artefact to
    the artefact bucket in the pipeline stack. See confluence page: https://govukverify.atlassian.net/wiki/x/24ExyQ
  - Signer: A stack which allows us to provision signing infrastructure to sign artefacts uploaded to the pipeline bucket.
    See confluence page: https://govukverify.atlassian.net/wiki/x/24ExyQ
  - API Gateway logging stack: A stack which deploys a role to allow API Gateway to push logs to cloudwatch
    See confluence page: https://govukverify.atlassian.net/wiki/x/IYBJyQ
  - Infra audit hook: A stack which audits our infrastructure changes
    See confluence page: https://govukverify.atlassian.net/wiki/x/7IExyQ
  - Lambda audit hook: A stack which audits our lambda changes
    See confluence page: https://govukverify.atlassian.net/wiki/x/MYBHyQ
BASE_STACKS
}

if [ $# -lt 1 ]; then
  usage
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "${1}" in
    -l | --list-base-stacks)
      list_base_stacks
      exit 0
      ;;
    -b | --base-stacks)
      PROVISION_BASE_STACKS=true
      ;;
    -p | --pipelines)
      PROVISION_PIPELINE_STACK=true
      ;;
    -v | --vpc)
      PROVISION_VPC_STACK=true
      ;;
    -t | --txma)
      PROVISION_TXMA_STACK=true
      ;;
    -c | --cloudwatch-alarm)
      PROVISION_CLOUDWATCH_ALARM_STACK=true
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
done

function provision_base_stacks() {
  export AWS_REGION="eu-west-2"
  echo "Provisioning base stacks"

  #Signer stack
  echo "Provisioning signer stack"

  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/signer/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "signer" "signer" "${SIGNER_STACK_VERSION}"
  #Github Identity provider stack
  echo "Provisioning Github identity provider stack"
  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/github-identity/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "github-identity" "github-identity" "${GITHUB_IDENTITY_STACK_VERSION}"

  #API Gateway logging stack
  echo "Provisioning API Gateway logging stack"
  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/api-gateway-logs/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" api-gateway-logs api-gateway-logs "${API_GATEWAY_LOGGING_STACK_VERSION}"

  #Infra audit hook stack
  echo "Provisioning infrastructure audit hook script"
  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/infrastructure-audit-hook/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" infrastructure-audit-hook infrastructure-audit-hook LATEST

  # Lambda audit hook stack
  echo "Provisioning lambda audit hook script"
  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/lambda-audit-hook/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" lambda-audit-hook lambda-audit-hook LATEST

  echo "Provisioned base stacks"
}

function provision_vpc_stack() {
  export AWS_REGION="eu-west-2"

  echo "Provisioning VPC stack"

  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/vpc/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "vpc" "vpc" "${VPC_STACK_VERSION}"
  echo "Provisioned VPC stack"
}

function provision_txma_stack() {
  export AWS_REGION="eu-west-2"

  echo "Provisioning manual TxMA stack"
  TEMPLATE_FILE="$(pwd)/manual-stacks/txma/template.yml"
  if [ ! -f "${TEMPLATE_FILE}" ]; then
    echo "Could not find the manual TxMA template stack at path: ${TEMPLATE_FILE}"
    exit 1
  fi

  ${LOCAL_PROVISION_COMMAND} "${ENVIRONMENT}" "orchestration-${ENVIRONMENT}-txma" "${TEMPLATE_FILE}"
  echo "Provisioned TxMA stack"
}

function provision_cloudwatch_alarm_stack() {
  export AWS_REGION="eu-west-2"

  echo "Provisioning cloudwatch alarm stack"
  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/cloudwatch-alarm-stack/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "cloudwatch-alarm-stack" "cloudwatch-alarm-stack" "${CLOUDWATCH_ALARM_STACK_VERSION}"
  echo "Provisioned cloudwatch alarm stack"
}

function provision_pipeline_stack() {
  export AWS_REGION="eu-west-2"
  echo "Provisioning secure pipeline stack"

  PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/${ENVIRONMENT}-orch-be-pipeline/parameters.json" ${PROVISION_COMMAND} "${ENVIRONMENT}" "${ENVIRONMENT}-orch-be-pipeline" "sam-deploy-pipeline" "${SECURE_PIPELINE_STACK_VERSION}"

  echo "Provisioned secure pipeline stack"
}

# --------------------
# Run provision commands
# --------------------

# Must deploy these first as the pipeline depends on them

[ "${PROVISION_BASE_STACKS}" == "true" ] && provision_base_stacks
[ "${PROVISION_VPC_STACK}" == "true" ] && provision_vpc_stack

# Now we can deploy the pipeline stack

[ "${PROVISION_PIPELINE_STACK}" == "true" ] && provision_pipeline_stack

#These are "extra" stacks

#This stack currently has a dependency on the main application stack for the SNS topic
[ "${PROVISION_TXMA_STACK}" == "true" ] && provision_txma_stack
#This stack currently has a dependency on the main application stack for the SNS topic
[ "${PROVISION_CLOUDWATCH_ALARM_STACK}" == "true" ] && provision_cloudwatch_alarm_stack
