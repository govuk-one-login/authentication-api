#!/usr/bin/env bash
set -euo pipefail

# Ensure we're in the root directory of the repo
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

environments=("authdev1" "authdev2" "authdev3" "dev")

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
    $0 [options]

Options:
    -b, --build                 run gradle and buildZip tasks
    --no-build                  do not run gradle and buildZip tasks
    -p, --prompt                prompt for confirmation before sam deploy
    -c, --clean                 run gradle clean before build
    -h, --help                  display this help message
    -x, --authapi               deploy the Auth Int & ext API
    -s  --Stubsapi              deploy the Stubs API

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
  export AWS_PROFILE=di-authentication-development-admin
  export AWS_REGION="eu-west-2"

  if ! aws sts get-caller-identity &> /dev/null; then
    aws sso login --profile "${AWS_PROFILE}"
  fi
}

O_BUILD=0          # -b, --build
O_CLEAN=""         # -c, --clean
O_DEPLOYAUTHAPI=0  # -x, --auth-internal-external-api
O_DEPLOYSTUBSAPI=0 # -s, --stubs-api
AUTHAPI_TEMPLATE_FILE="${TEMPLATE_FILE:-${DIR}/auth-template.yaml}"
STUBSAPI_TEMPLATE_FILE="${TEMPLATE_FILE:-${DIR}/stubs-template.yaml}"
SAMCONFIG_FILE=${SAMCONFIG_FILE:-${DIR}/scripts/dev-samconfig.toml}
CONFIRM_CHANGESET_OPTION="--no-confirm-changeset"

while [[ $# -gt 0 ]]; do
  case "${1}" in
    -b | --build) O_BUILD=1 ;;
    --no-build) O_BUILD=0 ;;
    -p | --prompt) CONFIRM_CHANGESET_OPTION="--confirm-changeset" ;;
    -c | --clean) O_CLEAN="clean" ;;
    -x | --authapi) O_DEPLOYAUTHAPI=1 ;;
    -s | --stubsapi) O_DEPLOYSTUBSAPI=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage
      exit 1
      ;;
    *)
      echo "Error: Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

echo "Select environment:"
select env in "${environments[@]}"; do
  if [[ -n ${env} ]]; then
    ENVIRONMENT=${env}
    break
  else
    echo "Invalid selection. Please try again."
  fi
done
echo "You are going to deploy in ${ENVIRONMENT}"
read -r -p "Press enter to continue or Ctrl+C to abort"
echo "Environment: ${ENVIRONMENT}"

if [[ ${O_BUILD} -eq 1 ]]; then
  echo "Building deployment artefacts ... "
  ./gradlew --no-daemon --parallel ${O_CLEAN} buildZip
  echo "done!"
fi

if [[ ${O_DEPLOYAUTHAPI} -eq 1 ]]; then
  sso_login

  echo "Merging all ${DIR}/ci/cloudformation/auth templates into a single ${AUTHAPI_TEMPLATE_FILE}"
  # shellcheck disable=SC2046
  rain merge $(find "${DIR}/ci/cloudformation/auth" -type f \( -name "*.yaml" -o -name "*.yml" \) -print) -o "${AUTHAPI_TEMPLATE_FILE}"

  echo "Lint template file"
  sam validate --lint --template-file="${AUTHAPI_TEMPLATE_FILE}"

  echo "Running sam build on template file"
  sam build --parallel --template-file="${AUTHAPI_TEMPLATE_FILE}"

  sam deploy \
    --no-fail-on-empty-changeset \
    --config-env "${ENVIRONMENT}" \
    --config-file "${SAMCONFIG_FILE}" \
    ${CONFIRM_CHANGESET_OPTION}

  echo "Deployment complete!"
fi

if [[ ${O_DEPLOYSTUBSAPI} -eq 1 ]]; then
  sso_login

  if [[ ${ENVIRONMENT} == "dev" ]]; then
    SAM_CONFIG_ENV="devstubs"
  elif [[ ${ENVIRONMENT} == "authdev1" ]]; then
    SAM_CONFIG_ENV="authdev1stubs"
  elif [[ ${ENVIRONMENT} == "authdev2" ]]; then
    SAM_CONFIG_ENV="authdev2stubs"
  elif [[ ${ENVIRONMENT} == "authdev3" ]]; then
    SAM_CONFIG_ENV="authdev3stubs"
  else
    SAM_CONFIG_ENV="${ENVIRONMENT}"
  fi

  echo "Merging all ${DIR}/ci/cloudformation/stubs templates into a single ${STUBSAPI_TEMPLATE_FILE}"
  # shellcheck disable=SC2046
  rain merge $(find "${DIR}/ci/cloudformation/stubs" -type f \( -name "*.yaml" -o -name "*.yml" \) -print) -o "${STUBSAPI_TEMPLATE_FILE}"

  echo "Lint template file"
  sam validate --lint --template-file="${STUBSAPI_TEMPLATE_FILE}"

  echo "Running sam build on template file"
  sam build --parallel --template-file="${STUBSAPI_TEMPLATE_FILE}"

  sam deploy \
    --no-fail-on-empty-changeset \
    --config-env "${SAM_CONFIG_ENV}" \
    --config-file "${SAMCONFIG_FILE}" \
    ${CONFIRM_CHANGESET_OPTION}

  echo "Deployment complete!"
fi
