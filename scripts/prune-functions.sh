#!/usr/bin/env bash
FUNCTION_PREFIX=$1
VERSIONS_TO_KEEP=5

FUNCTIONS="$(aws lambda list-functions | jq -r '.Functions[] | select(.FunctionName | startswith($environment) and (endswith("warmer") | not) ).FunctionName' --arg environment "${FUNCTION_PREFIX}")"

echo "${FUNCTIONS}" | while IFS= read -r FUNCTION; do
    echo "Getting versions for ${FUNCTION}"
    VERSIONS="$(aws lambda list-versions-by-function --function-name "${FUNCTION}" | jq -rc '[.Versions[] | select(.Version != "$LATEST").Version | tonumber]')"
    if [ "${VERSIONS}" != '[]' ]; then
      PRUNE_VERSION="$(echo "${VERSIONS}" | jq -r 'max - ($keep | tonumber)' --arg keep "${VERSIONS_TO_KEEP}")"
      VERSIONS_TO_PRUNE="$(echo "${VERSIONS}" | jq -c '[.[] | select( . <= ($max | tonumber))]' --arg max "${PRUNE_VERSION}")"
      echo "Pruning $(echo "${VERSIONS_TO_PRUNE}" | jq -r length ) version(s) prior to version ${PRUNE_VERSION}..."
      echo "${VERSIONS_TO_PRUNE}" | jq -r '.[]' | xargs -r -n 1 aws lambda delete-function --output text --function-name "${FUNCTION}" --qualifier
    fi
done

#gds-cli aws digital-identity-dev -- ./scripts/prune-functions.sh <environment-name>