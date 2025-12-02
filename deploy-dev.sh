#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

environments=("authdev1" "authdev2" "authdev3" "sandpit")

function usage() {
  cat <<- USAGE
Usage:
    $0 [options] <environment>

Options:
    -b, --build                 run gradle and buildZip tasks before applying the Terraform configuration. (default: true)
    --no-build                  do not run gradle and buildZip tasks before applying the Terraform configuration. (default: false)
    -p, --prompt                prompt for confirmation before applying the Terraform configuration. (default: false)
    -c, --clean                 run gradle clean before build. (default: false)
    --shell                     start a shell in the Terraform configuration directory. (does not automatically apply) (default: false)
    -r, --refresh-only          only refresh the Terraform configuration without applying it. (default: false)
    -h, --help                  display this help message.

    -a, --account-management    deploy the account-management API. (default: true)
    -x, --auth-external         deploy the auth-external API. (default: true)
    --ticf-stub                 deploy the TICF CRI stub. (default: true)
    -d, --delivery-receipts     deploy the delivery receipts API. (default: false)
    -o, --oidc                  deploy the OIDC API. (default: true)
    -u, --utils                 deploy the utils API. (default: false)
    -s, --shared                deploy the shared Terraform configuration. (default: true)
    -i, --interventions         deploy the account interventions API stub. (default: true)
    -t, --test-services         deploy the test services API. (default: false)

Arguments:
    environment                 the environment to deploy to. Valid environments are: ${environments[*]}
USAGE
}

#O_PROMPT=0 # -p, --prompt
O_BUILD=0   # -b, --build
O_CLEAN=""  # -c, --clean
O_SHELL=0   # --shell
O_REFRESH=0 # -r, --refresh-only

T_ACCOUNT_MANAGEMENT=0     # -a, --account-management
T_AUTH_EXTERNAL_API=0      # -x, --auth-external
T_TICF_CRI_STUB=0          # --ticf-stub
T_DELIVERY_RECEIPTS=0      # -d, --delivery-receipts
T_OIDC=0                   # -o, --oidc
T_UTILS=0                  # -u, --utils
T_SHARED=0                 # -s, --shared
T_INTERVENTIONS_API_STUB=0 # -i, --interventions, --interventions-stub
T_TEST_SERVICE=0           # -t, --test-services

POSITIONAL=()
NUMBER_PICKED=0
ENVIRONMENT=""

AUTO_APPROVE="-auto-approve"

while (($#)); do
  case $1 in
    -b | --build) O_BUILD=1 ;;
    --no-build) O_BUILD=0 ;;
    -p | --prompt) AUTO_APPROVE="" ;;
    -c | --clean) O_CLEAN="clean" ;;
    --shell) O_SHELL=1 ;;
    -r | --refresh-only) O_REFRESH=1 ;;

    -a | --account-management) T_ACCOUNT_MANAGEMENT=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -x | --auth-external) T_AUTH_EXTERNAL_API=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    --ticf-stub) T_TICF_CRI_STUB=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -d | --delivery-receipts) T_DELIVERY_RECEIPTS=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -o | --oidc) T_OIDC=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -u | --utils) T_UTILS=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -s | --shared) T_SHARED=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -i | --interventions | --interventions-stub) T_INTERVENTIONS_API_STUB=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    -t | --test-services) T_TEST_SERVICE=1 NUMBER_PICKED=$((NUMBER_PICKED + 1)) ;;
    --all) T_ACCOUNT_MANAGEMENT=1 T_AUTH_EXTERNAL_API=1 T_TICF_CRI_STUB=1 T_DELIVERY_RECEIPTS=1 T_OIDC=1 T_UTILS=1 T_SHARED=1 T_INTERVENTIONS_API_STUB=1 T_TEST_SERVICE=1 NUMBER_PICKED=-1 ;;

    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "Error: Unknown option: $1"
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

if [[ ${ENVIRONMENT} =~ ^authdev ]]; then
  export AWS_PROFILE="di-auth-development-AdministratorAccessPermission"
else
  export AWS_PROFILE="gds-di-development-admin"
fi

if [[ ${NUMBER_PICKED} -eq 0 ]]; then
  O_BUILD=1
  T_ACCOUNT_MANAGEMENT=1
  T_AUTH_EXTERNAL_API=1
  T_TICF_CRI_STUB=1
  T_OIDC=1
  T_SHARED=1
  T_INTERVENTIONS_API_STUB=1
fi

if [[ ${O_BUILD} -eq 1 ]]; then
  echo "Building deployment artefacts ... "
  pushd "${DIR}" > /dev/null
  ./gradlew ${O_CLEAN} buildZip -PdevDeployBuild=1
  popd > /dev/null
  echo "done!"
fi

echo "Ensuring AWS CLI is configured ..."
# Test if the AWS CLI is configured with the correct profile
if ! sso_session="$(aws configure get sso_session --profile "${AWS_PROFILE}")"; then
  echo "AWS CLI profile ${AWS_PROFILE} is not configured."
  echo "Please visit https://govukverify.atlassian.net/wiki/x/IgFm5 for instructions."
  exit 1
fi
if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" > /dev/null; then
  aws sso login --sso-session "${sso_session}"
fi

configured_region="$(aws configure get region --profile "${AWS_PROFILE}" 2> /dev/null || true)"
export AWS_REGION="${configured_region:-eu-west-2}"

echo -n "Retrieving Terraform variables from Secrets Manager ... "
source "${DIR}/scripts/read_secrets__main.sh" "${ENVIRONMENT}"
echo "done!"

export TF_VAR_environment="${ENVIRONMENT}"

function run_terraform() {
  local component="${1}"
  echo "Running ${component} Terraform ..."
  pushd "${DIR}/ci/terraform/${component}" > /dev/null
  terraform init -reconfigure -backend-config="${ENVIRONMENT}".hcl

  if [[ ${O_SHELL} -eq 1 ]]; then
    ${SHELL} -i
  elif [[ ${O_REFRESH} -eq 1 ]]; then
    terraform refresh -var-file "${ENVIRONMENT}".tfvars
  else
    terraform apply -var-file "${ENVIRONMENT}".tfvars "${AUTO_APPROVE}"
  fi
  popd > /dev/null
}

if [[ ${T_SHARED} -eq 1 ]]; then
  run_terraform "shared"
fi

if [[ ${T_OIDC} -eq 1 ]]; then
  run_terraform "oidc"
fi

if [[ ${T_INTERVENTIONS_API_STUB} -eq 1 ]]; then
  run_terraform "interventions-api-stub"
fi

if [[ ${T_TICF_CRI_STUB} -eq 1 ]]; then
  run_terraform "ticf-cri-stub"
fi

if [[ ${T_ACCOUNT_MANAGEMENT} -eq 1 ]]; then
  run_terraform "account-management"
fi

if [[ ${T_DELIVERY_RECEIPTS} -eq 1 ]]; then
  run_terraform "delivery-receipts"
fi

if [[ ${T_UTILS} -eq 1 ]]; then
  run_terraform "utils"
fi

if [[ ${T_TEST_SERVICE} -eq 1 ]]; then
  run_terraform "test-services"
fi

if [[ ${T_AUTH_EXTERNAL_API} -eq 1 ]]; then
  run_terraform "auth-external-api"
fi
