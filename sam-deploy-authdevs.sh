#!/usr/bin/env bash
set -euo pipefail

# Ensure we're in the root directory of the repo
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

environments=("authdev1" "authdev2" "dev")

# -------------
# Prerequisites
# -------------
if ! command -v rain &> /dev/null; then
  echo "Merging templates requires rain to be installed. See https://github.com/aws-cloudformation/rain for installation instructions."
  exit 1
fi

if ! command -v sam &> /dev/null; then
  echo "Deploying template requires AWS sam cli to be installed. See https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html for installation instructions."
  exit 1
fi

function usage() {
  cat <<- USAGE
Usage:
    $0 [options] <environment>

Options:
    -b, --build                 run gradle and buildZip tasks
    --no-build                  do not run gradle and buildZip tasks
    -p, --prompt                prompt for confirmation before sam deploy
    -c, --clean                 run gradle clean before build
    -h, --help                  display this help message

    -o, --oidc                  deploy the OIDC API
    -x, --auth-external         deploy the auth-external API

Arguments:
    environment                 the environment to deploy to. Valid environments are: ${environments[*]}

Dependencies:
    AWS CLI, AWS SAM, rain
USAGE
}

if [ $# -lt 1 ]; then
  usage
  exit 1
fi

function sso_login() {
  export AWS_ACCOUNT=di-authentication-development
  export AWS_PROFILE=di-authentication-development-AWSAdministratorAccess
  export AWS_REGION="eu-west-2"

  if ! aws sts get-caller-identity &> /dev/null; then
    aws sso login --profile "${AWS_PROFILE}"
  fi
}

O_BUILD=0  # -b, --build
O_CLEAN="" # -c, --clean
O_DEPLOY=0 # -x, --auth-external

POSITIONAL=()
TEMPLATE_FILE="${TEMPLATE_FILE:-${DIR}/auth-template.yaml}"
SAMCONFIG_FILE=${SAMCONFIG_FILE:-${DIR}/scripts/dev-samconfig.toml}
CONFIRM_CHANGESET_OPTION="--no-confirm-changeset"

while [[ $# -gt 0 ]]; do
  case "${1}" in
    -b | --build) O_BUILD=1 ;;
    --no-build) O_BUILD=0 ;;
    -p | --prompt) CONFIRM_CHANGESET_OPTION="--confirm-changeset" ;;
    -c | --clean) O_CLEAN="clean" ;;
    -o | --oidc) O_DEPLOY=1 ;;
    -x | --auth-external) O_DEPLOY=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage
      exit 1
      ;;
    *) POSITIONAL+=("$1") ;;
  esac
  shift
done

if [[ ${#POSITIONAL[@]} -gt 1 ]]; then
  echo "Error: only 1 environment can be specified"
  exit 1
elif [[ ${#POSITIONAL[@]} -eq 0 ]]; then
  echo "Error: Environment must be specified. Valid environments are: ${environments[*]}"
  exit 1
fi

if [[ ! " ${environments[*]} " =~ ${POSITIONAL[0]} ]]; then
  echo "Error: invalid environment specified: ${POSITIONAL[0]}"
  exit 1
fi
ENVIRONMENT=${POSITIONAL[0]}
echo "Environment: ${ENVIRONMENT}"

if [[ ${O_BUILD} -eq 1 ]]; then
  echo "Building deployment artefacts ... "
  ./gradlew --no-daemon --parallel ${O_CLEAN} :auth-external-api:buildZip :frontend-api:buildZip
  echo "done!"
fi

if [[ ${O_DEPLOY} -eq 1 ]]; then
  sso_login

  echo "Merging all ${DIR}/ci/cloudformation/auth templates into a single ${TEMPLATE_FILE}"
  # shellcheck disable=SC2046
  rain merge $(find "${DIR}/ci/cloudformation/auth" -type f \( -name "*.yaml" -o -name "*.yml" \) -print) -o "${TEMPLATE_FILE}"

  echo "Lint template file"
  sam validate --lint --template-file="${TEMPLATE_FILE}"

  echo "Running sam build on template file"
  sam build --parallel --template-file="${TEMPLATE_FILE}"

  sam deploy \
    --no-fail-on-empty-changeset \
    --config-env "${ENVIRONMENT}" \
    --config-file "${SAMCONFIG_FILE}" \
    ${CONFIRM_CHANGESET_OPTION}

  echo "Deployment complete!"
fi
