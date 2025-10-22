#!/usr/bin/env bash
VERSIONS_TO_KEEP=$1

if [[ ${VERSIONS_TO_KEEP} -lt 3 ]]; then
  echo "The minimum number of versions to keep is 3"
  exit 1
fi

FUNCTIONS="$(aws lambda list-functions | jq -r '.Functions[].FunctionName')"

echo "${FUNCTIONS}" | while IFS= read -r FUNCTION; do
  echo "Getting versions for ${FUNCTION}"
  VERSIONS="$(aws lambda list-versions-by-function --function-name "${FUNCTION}" | jq -rc '[.Versions[] | select(.Version != "$LATEST").Version | tonumber]')"
  if [ "${VERSIONS}" != '[]' ]; then
    PRUNE_VERSION="$(echo "${VERSIONS}" | jq -r 'max - ($keep | tonumber)' --arg keep "${VERSIONS_TO_KEEP}")"
    VERSIONS_TO_PRUNE="$(echo "${VERSIONS}" | jq -c '[.[] | select( . <= ($max | tonumber))]' --arg max "${PRUNE_VERSION}")"
    echo "Pruning $(echo "${VERSIONS_TO_PRUNE}" | jq -r length) version(s) prior to version ${PRUNE_VERSION}..."
    echo "${VERSIONS_TO_PRUNE}" | jq -r '.[]' | xargs -r -n 1 aws lambda delete-function --output text --function-name "${FUNCTION}" --qualifier
  fi
done
