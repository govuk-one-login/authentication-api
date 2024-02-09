#!/usr/bin/env bash
ENVIRONMENT=${1}

PROVISION_COMMAND="../../../devplatform-deploy/stack-orchestration-tool/provisioner.sh"

export AUTO_APPLY_CHANGESET=true
export SKIP_AWS_AUTHENTICATION=true
export AWS_PAGER=""

# Provision dependencies
for dir in configuration/"$ENVIRONMENT"/*/; do
  # shellcheck disable=SC2086
  STACK=$(basename "$dir")
  if [[ $STACK != "$ENVIRONMENT-orch-be-pipeline" && -f configuration/$ENVIRONMENT/$STACK/parameters.json ]]; then
    $PROVISION_COMMAND "$ENVIRONMENT" "$STACK" "$STACK" LATEST &
  fi
done

### Provision secure pipelines
$PROVISION_COMMAND "$ENVIRONMENT" "$ENVIRONMENT-orch-be-pipeline" sam-deploy-pipeline LATEST