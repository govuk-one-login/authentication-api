#!/bin/bash
set -euo pipefail

environments=("authdev1" "authdev2" "sandpit" "dev")

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

echo "${ENVIRONMENT} ${EMAIL}"
