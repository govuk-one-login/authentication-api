#!/usr/bin/env bash

set -euo pipefail

source ./scripts/functions.sh
source ./scripts/test-api.sh

function usage() {
  cat <<USAGE
  A script to run the DCS unit, integration, and acceptance tests locally. Runs all tests by default.

  Usage:
    $0 [-dig]

  Options:
    -u  run the unit tests
    -i  run the integration tests
    -g  running in GitHub actions
USAGE
}
RUN_UNIT=0
RUN_INTEGRATION=0
IN_GITHUB_ACTIONS=0

if [[ $# -eq 0 ]] || [[ ( $# -eq 1 && ${1} == "-l" ) ]]; then
  RUN_UNIT=1
  RUN_INTEGRATION=1
fi

while getopts "uig" opt; do
  case ${opt} in
    u)
      RUN_UNIT=1
      ;;
    i)
      RUN_INTEGRATION=1
      ;;
    g)
      IN_GITHUB_ACTIONS=1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [[ ${RUN_UNIT} -eq 1 ]]; then
  printf "\nRunning build and unit tests...\n"

  set +e
  ./gradlew clean build -x integration-tests:test
  build_and_test_exit_code=$?
  set -e
  if [ ${build_and_test_exit_code} -ne 0 ]; then
    printf "\nBuild and test failed.\n"
    exit 1
  fi
fi

if [[ ${RUN_INTEGRATION} -eq 1 ]]; then
  export TF_VAR_notify_url="http://notify.internal:8888"
  export TF_VAR_notify_api_key="my_test_key-$(uuidgen)-$(uuidgen)"
  export AWS_ACCESS_KEY_ID="mock-access-key"
  export AWS_SECRET_ACCESS_KEY="mock-secret-key"
  startup

  set +e
  run-integration-tests
  build_and_test_exit_code=$?
  set -e

  stop_docker_services aws redis dynamodb
fi

if [ ${build_and_test_exit_code} -ne 0 ]; then
  printf "\npre-commit failed.\n"
else
  if [[ ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_success
  fi
fi
