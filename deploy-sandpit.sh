#!/usr/bin/env bash

set -eu
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function runTerraform() {
  echo "Running ${1} Terraform..."
  pushd "${DIR}/ci/terraform/${1}" > /dev/null
  rm -rf .terraform/
  terraform init -backend-config=sandpit.hcl
  terraform apply -var-file sandpit.tfvars ${2}
  popd > /dev/null
}

function usage() {
  cat <<USAGE
  A script to deploy the GOV.UK Sign in APIs to the sandpit environment.
  Requires a GDS CLI, AWS CLI and jq installed and configured.

  Usage:
    $0 [-b|--build] [-c|--clean] [-s|--shared] [-o|--oidc] [-a|--account-management] [--audit] [--destroy] [-p|--prompt]

  Options:
    -b, --build               run gradle build and buildZip tasks (default)
    -c, --clean               run gradle clean before build
    -s, --shared              run the shared terraform (default)
    -o, --oidc                run the oidc terraform (default)
    -a, --account-management  run the account management terraform (default)
    --audit                   run the audit terraform
    -d, --delivery-receipts   run the delivery receipts terraform
    -u, --utils               run the utils terraform
    --destroy                 run all terraform with the -destroy flag (destroys all managed resources)
    -p, --prompt              will prompt for plan review before applying any terraform

    If no options specified the default actions above will be carried out without prompting.
USAGE
}

AM=0
AUDIT=0
BUILD=0
OIDC=0
RECEIPTS=0
SHARED=0
UTILS=0
CLEAN=""
TERRAFORM_OPTS="-auto-approve"
if [[ $# == 0 ]]; then
  AM=1
  BUILD=1
  OIDC=1
  SHARED=1
  UTILS=1
fi
while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--account-management)
      AM=1
      ;;
    --audit)
      AUDIT=1
      ;;
    -b|--build)
      BUILD=1
      ;;
    -c|--clean)
      CLEAN="clean"
      ;;
    -d|--delivery-receipts)
      RECEIPTS=1
      ;;
    -o|--oidc)
      OIDC=1
      ;;
    -s|--shared)
      SHARED=1
      ;;
    -u|--utils)
      UTILS=1
      ;;
    --destroy)
      TERRAFORM_OPTS="-destroy"
      ;;
    -p|--prompt)
      TERRAFORM_OPTS=""
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
  pushd "${DIR}" > /dev/null
  ./gradlew ${CLEAN} build buildZip -x test -x spotlessCheck -x composeDown
  popd > /dev/null
  echo "done!"
fi

echo -n "Getting AWS credentials ... "
eval $(gds aws digital-identity-dev -e)
echo "done!"

echo -n "Getting Terraform variables from SSM ... "
VARS="$(aws ssm get-parameters-by-path --region eu-west-2 --with-decryption --path "/sandpit-deploy/terraform-variables" | jq -r '.Parameters[] | @base64')"
for VAR in $VARS; do
  VAR_NAME="TF_VAR_$(echo ${VAR} | base64 -d | jq -r '.Name / "/" | .[3]')"
  export $VAR_NAME="$(echo ${VAR} | base64 -d | jq -r '.Value')"
done
echo "done!"

if [[ $SHARED == "1" ]]; then
  runTerraform "shared" "${TERRAFORM_OPTS}"
fi
if [[ $OIDC == "1" ]]; then
  runTerraform "oidc" "${TERRAFORM_OPTS}"
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
