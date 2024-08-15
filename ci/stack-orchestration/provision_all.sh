#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null || usage "Error: Unable to change to script directory."

ENVIRONMENT=${1}

PROVISIONER_SCRIPT="./.devplatform-deploy/stack-orchestration-tool/provisioner.sh"
if [[ ! -f ${PROVISIONER_SCRIPT} ]]; then
  echo 'Provisioner script not found. You probably need to pull the submodule: git submodule update --init --recursive'
  exit 1
fi
cp "${PROVISIONER_SCRIPT}" .

export AUTO_APPLY_CHANGESET=true
export SKIP_AWS_AUTHENTICATION=true
export AWS_PAGER=""

# Provision dependencies
for directory in configuration/"${ENVIRONMENT}"/*/; do
  STACK=$(basename "${directory}")
  if [[ ${STACK} != "${ENVIRONMENT}-orch-be-pipeline" && -f "configuration/${ENVIRONMENT}/${STACK}/parameters.json" ]]; then
    if [[ -f "configuration/${ENVIRONMENT}/${STACK}/.disable" ]]; then
      echo "Skipping ${STACK}, due to presence of .disable file"
      continue
    fi
    ./provisioner.sh "${ENVIRONMENT}" "${STACK}" "${STACK}" LATEST
  fi
done

### Provision secure pipelines
./provisioner.sh "${ENVIRONMENT}" "${ENVIRONMENT}-orch-be-pipeline" sam-deploy-pipeline LATEST
