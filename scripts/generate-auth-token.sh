#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
cd "${DIR}" || exit 1

environments=("authdev1" "authdev2" "dev" "build")

function usage() {
  cat <<- USAGE
Creates an access token that can be used for direct account management API queries. Expires in 12 hours.

Usage:
    $0 <environment> <email address>

Options:
    -h, --help                  display this help message.

Arguments:
    environment                 the environment to target to. Valid environments are: ${environments[*]}
    email address               the email address to create an access token for
USAGE
}

POSITIONAL=()
ENVIRONMENT=""

while (($#)); do
  case $1 in
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

if [[ ${#POSITIONAL[@]} -ne 2 ]]; then
  echo "Error: need just an environment and email address provided"
  exit 1
fi

ENVIRONMENT="${POSITIONAL[0]}"
EMAIL="${POSITIONAL[1]}"

if [[ ${ENVIRONMENT} == "authdev1" ]]; then
  export AWS_PROFILE="di-auth-development-admin"
  KMS_KEY_ARN="arn:aws:kms:eu-west-2:653994557586:alias/authdev1-id-token-signing-key-alias"
  CLIENT_ID="skwdHH2y6ERjJWTPSoAFbSt8lX04OgtI"
elif [[ ${ENVIRONMENT} == "authdev2" ]]; then
  export AWS_PROFILE="di-auth-development-admin"
  KMS_KEY_ARN="arn:aws:kms:eu-west-2:653994557586:alias/authdev2-id-token-signing-key-alias"
  CLIENT_ID="rPEUe0hRrHqf0i0es1gYjKxE5ceGN7VK"
elif [[ ${ENVIRONMENT} == "dev" ]]; then
  export AWS_PROFILE="di-auth-development-admin"
  KMS_KEY_ARN="arn:aws:kms:eu-west-2:653994557586:alias/dev-id-token-signing-key-alias"
  CLIENT_ID="J3tedNRsfssnsf4STuc2NNIV1C1gdxBB"
elif [[ ${ENVIRONMENT} == "build" ]]; then
  export AWS_PROFILE="gds-di-development-admin"
  KMS_KEY_ARN="arn:aws:kms:eu-west-2:761723964695:alias/build-id-token-signing-key-alias"
  CLIENT_ID="P5OQvWV21U0OW7U5g27d6MU2LLznYYaM"
fi

configured_region="$(aws configure get region --profile "${AWS_PROFILE}" 2> /dev/null || true)"
export AWS_REGION="${configured_region:-eu-west-2}"

INTERNAL_COMMON_SUBJECT_ID=$("${DIR}/export-ics.sh" "${EMAIL}" "${ENVIRONMENT}" | tail -n 1)
if [[ ${INTERNAL_COMMON_SUBJECT_ID} == *"does not exist"* ]]; then
  echo "${INTERNAL_COMMON_SUBJECT_ID}"
  exit 1
fi

echo "Checking npm dependencies"
npm install --no-audit --no-fund
echo

./_generate-auth-token.js "${INTERNAL_COMMON_SUBJECT_ID}" "${CLIENT_ID}" "${KMS_KEY_ARN}"
