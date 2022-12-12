#!/usr/bin/env bash

set -eu
DIR="$(git rev-parse --show-toplevel)"
pushd "${DIR}" > /dev/null
export DOCKER_DEFAULT_PLATFORM=linux/amd64
TERRAFORM_VERSION=$(cat ci/terraform/.terraform-version)

function runTerraformValidate() {
  echo "Running Terraform Validate in ${1}..."
  export DATA_DIR="build/precommit/${1}"
  export TF_DATA_DIR="/src/${DATA_DIR}"
  mkdir -p "${DIR}/${DATA_DIR}"
  rm -rf "${DIR}/${DATA_DIR}/*"
  export TF_IN_AUTOMATION=1
  docker run \
    -v "${DIR}:/src" \
    -e TF_DATA_DIR \
    -e TF_IN_AUTOMATION \
    "hashicorp/terraform:${TERRAFORM_VERSION}" \
    -chdir="/src/${1}" \
    init -backend=false

  docker run \
    -v "${DIR}:/src" \
    -e TF_DATA_DIR \
    -e TF_IN_AUTOMATION \
    "hashicorp/terraform:${TERRAFORM_VERSION}" \
    -chdir="/src/${1}" \
    validate
}

DIRECTORIES=($(for dir in $(dirname "$@"); do
  echo ${dir}
done | sort -u))

for TERRAFORM_DIR in "${DIRECTORIES[@]}"; do
  runTerraformValidate "${TERRAFORM_DIR}"
done

popd > /dev/null
