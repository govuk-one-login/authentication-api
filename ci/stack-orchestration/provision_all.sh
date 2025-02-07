#!/usr/bin/env bash
ENVIRONMENT=${1}

PROVISION_COMMAND="../../../devplatform-deploy/stack-orchestration-tool/provisioner.sh"
TAGS_FILE="$(pwd)/configuration/${ENVIRONMENT}/tags.json"

export AUTO_APPLY_CHANGESET=true
export SKIP_AWS_AUTHENTICATION=true
export AWS_PAGER=""
export TAGS_FILE

# Provision dependencies
for dir in configuration/"${ENVIRONMENT}"/*/; do
  # shellcheck disable=SC2086
  STACK=$(basename "${dir}")
  if [[ ${STACK} != "${ENVIRONMENT}-orch-be-pipeline" && -f configuration/${ENVIRONMENT}/${STACK}/parameters.json ]]; then
    PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/${STACK}/parameters.json"
    export PARAMETERS_FILE
    ${PROVISION_COMMAND} "${ENVIRONMENT}" "${STACK}" "${STACK}" LATEST &
  fi
done

### Provision secure pipelines
PARAMETERS_FILE="$(pwd)/configuration/${ENVIRONMENT}/${ENVIRONMENT}-orch-be-pipeline/parameters.json"
export PARAMETERS_FILE
${PROVISION_COMMAND} "${ENVIRONMENT}" "${ENVIRONMENT}-orch-be-pipeline" sam-deploy-pipeline LATEST
