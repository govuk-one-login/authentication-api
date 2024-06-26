#!/usr/bin/env bash
set -euo pipefail

[[ "${BASH_SOURCE[0]}" != "${0}" ]] || {
    echo "Error: Script must be sourced, not executed"
    exit 1
}

function runTerraform() {
    echo "Running ${1} Terraform..."
    pushd "${DIR}/ci/terraform/${1}" >/dev/null
    rm -rf .terraform/
    terraform init -backend-config="${DEPLOY_ENV}".hcl
    if [ "${RUN_SHELL}" == "1" ]; then
        ${SHELL} -i
    else
        terraform apply -var-file "${DEPLOY_ENV}".tfvars "${2}"
    fi
    popd >/dev/null
}

function usage() {
    cat <<USAGE
  A script to deploy the GOV.UK Sign in APIs to a development environment.
  Requires a GDS CLI, AWS CLI and jq installed and configured.

  Usage:
    $0 [-b|--build] [-c|--clean] [-s|--shared] [-i|--interventions] [-o|--oidc] [-a|--account-management] [-t|--test-services] [--audit] [--destroy] [-p|--prompt] [-x|--auth-external]

  Options:
    -b, --build               run gradle build and buildZip tasks (default)
    -c, --clean               run gradle clean before build
    -s, --shared              run the shared terraform (default)
    -o, --oidc                run the oidc terraform (default)
    -i, --interventions       run the account interventions API stub terraform (default)
    -a, --account-management  run the account management terraform (default)
    --audit                   run the audit terraform
    -d, --delivery-receipts   run the delivery receipts terraform
    -u, --utils               run the utils terraform
    -t, --test-services       run the test services terraform
    --ticf-stub               run the TICF stub terraform
    --destroy                 run all terraform with the -destroy flag (destroys all managed resources)
    -p, --prompt              will prompt for plan review before applying any terraform
    -x, --auth-external       run the auth external api terraform
    --shell                   spawn an interactive shell inside the module directory after terraform init (does not apply)

    If no options specified the default actions above will be carried out without prompting.
USAGE
}

AM=0
AUDIT=0
AUTH_EXTERNAL_API=0
BUILD=0
OIDC=0
INTERVENTIONS=0
RECEIPTS=0
SHARED=0
UTILS=0
TEST_SERVICES=0
TICF_STUB=0

CLEAN=""
RUN_SHELL=0
TERRAFORM_OPTS="-auto-approve"

if [[ $# == 0 ]] || [[ $* == "-p" ]]; then
    AM=1
    AUTH_EXTERNAL_API=1
    BUILD=1
    OIDC=1
    INTERVENTIONS=1
    SHARED=1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
    -a | --account-management)
        AM=1
        ;;
    --audit)
        AUDIT=1
        ;;
    -b | --build)
        BUILD=1
        ;;
    -c | --clean)
        CLEAN="clean"
        ;;
    -d | --delivery-receipts)
        RECEIPTS=1
        ;;
    -o | --oidc)
        OIDC=1
        ;;
    -i | --interventions)
        INTERVENTIONS=1
        ;;
    -s | --shared)
        SHARED=1
        ;;
    -u | --utils)
        UTILS=1
        ;;
    -t | --test-services)
        TEST_SERVICES=1
        ;;
    --ticf-stub)
        TICF_STUB=1
        ;;
    --destroy)
        echo "PLEASE DON'T DESTROY, JUST REAPPLY"
        exit 1
        ;;
    -p | --prompt)
        TERRAFORM_OPTS=""
        ;;
    -r | --refresh)
        TERRAFORM_OPTS="-refresh-only"
        ;;
    -x | --auth-external)
        AUTH_EXTERNAL_API=1
        ;;
    --shell)
        # shellcheck disable=SC2034
        RUN_SHELL=1
        ;;
    *)
        usage
        exit 1
        ;;
    esac
    shift
done

if [[ $BUILD == "1" ]]; then
    echo "Building deployment artefacts ... "
    pushd "${DIR}" >/dev/null
    ./gradlew ${CLEAN} build buildZip -x test -x spotlessCheck -x composeDown
    popd >/dev/null
    echo "done!"
fi

source "${DIR}/scripts/export_aws_creds.sh"

echo -n "Getting Terraform variables from Secrets Manager ... "

source "${DIR}/scripts/read_secrets__main.sh" "${DEPLOY_ENV}"
echo "done!"

if [[ $SHARED == "1" ]]; then
    runTerraform "shared" "${TERRAFORM_OPTS}"
fi

if [[ $OIDC == "1" ]]; then
    runTerraform "oidc" "${TERRAFORM_OPTS}"
fi

if [[ $INTERVENTIONS == "1" ]]; then
    runTerraform "interventions-api-stub" "${TERRAFORM_OPTS}"
fi

if [[ $TICF_STUB == "1" ]]; then
    runTerraform "ticf-cri-stub" "${TERRAFORM_OPTS}"
fi

if [[ $AM == "1" ]]; then
    runTerraform "account-management" "${TERRAFORM_OPTS}"
fi

if [[ $AUDIT == "1" ]]; then
    runTerraform "audit" "${TERRAFORM_OPTS}"
fi

if [[ $RECEIPTS == "1" ]]; then
    runTerraform "delivery-receipts" "${TERRAFORM_OPTS}"
fi

if [[ $UTILS == "1" ]]; then
    runTerraform "utils" "${TERRAFORM_OPTS}"
fi

if [[ $TEST_SERVICES == "1" ]]; then
    runTerraform "test-services" "${TERRAFORM_OPTS}"
fi

if [[ $AUTH_EXTERNAL_API == "1" ]]; then
    runTerraform "auth-external-api" "${TERRAFORM_OPTS}"
fi
