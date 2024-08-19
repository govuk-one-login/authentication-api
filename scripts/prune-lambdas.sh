#!/usr/bin/env bash
# ----------------------------------------------------------------------------------------------------------------------
# Description:
# A script to remove old versions of lambdas.  The script requires AWS CLI credentials which should be set in the
# environment variables.  These credentials can be retrieved from the AWS access portal using 'Access keys' link
# and using 'Option 1: Set AWS environment variables', copy the export statements and paste them into the terminal
# before executing the script.
#
# Usage:
#   ./prune-lambdas.sh ENVIRONMENT
#
# Parameters:
#   ENVIRONMENT   -   The name of the environment to prune.  If not provided all lambdas will be pruned.
#
# ----------------------------------------------------------------------------------------------------------------------

set -euo pipefail

function usage() {
  cat << USAGE
  A script to remove old versions of lambdas.
  Requires AWS environment variables to be set:
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN

  Usage:
    $0 [-h|--help] ENVIRONMENT

  Options:
    -h, --help               displays this message
USAGE
}

FUNCTION_PREFIX=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -h | --help)
      usage
      exit 1
      ;;
    *)
      if [ -z "${FUNCTION_PREFIX}" ]; then
        FUNCTION_PREFIX="$1"
      else
        echo "Unexpected argument: $1"
        exit 1
      fi
      ;;
  esac
  shift
done

if [ -z "${FUNCTION_PREFIX}" ]; then
  read -r -p "This will prune all lambdas, continue? (y/n) " response
  case "${response}" in
    [yY][eE][sS] | [yY])
      echo "pruning all lambdas"
      ;;
    *)
      echo "Operation aborted by user."
      exit 1
      ;;
  esac
else
  echo "pruning lambdas with ${FUNCTION_PREFIX} prefix"
fi

VERSIONS_TO_KEEP=5

FUNCTIONS="$(aws lambda list-functions | jq -r '.Functions[] | select(.FunctionName | startswith($environment) and (endswith("warmer") | not) ).FunctionName' --arg environment "${FUNCTION_PREFIX}")"

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
