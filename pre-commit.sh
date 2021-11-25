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
    -i  run all integration tests
    -g  running in GitHub actions
    -s  run against sandpit
USAGE
}
RUN_UNIT=0
RUN_INTEGRATION=0
IN_GITHUB_ACTIONS=0
TF_ACCOUNT_MANAGEMENT=0
SANDPIT=0

if [[ $# -eq 0 ]] || [[ ( $# -eq 1 && ${1} == "-l" ) ]]; then
  RUN_UNIT=1
  RUN_INTEGRATION=1
fi

while getopts "uigts" opt; do
  case ${opt} in
    u)
      RUN_UNIT=1
      ;;
    i)
      RUN_INTEGRATION=1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

auth_api_pre_commit_start_seconds=$SECONDS

if [[ ${RUN_UNIT} -eq 1 ]]; then
  printf "\nRunning build and unit tests...\n"
  run_unit_tests_start_seconds=$SECONDS
  set +e
  ./gradlew --parallel clean build -x integration-tests:test -x account-management-integration-tests:test
  build_and_test_exit_code=$?
  set -e
  record_timings "run-unit-tests" run_unit_tests_start_seconds $SECONDS false
  if [ ${build_and_test_exit_code} -ne 0 ]; then
    printf "\nBuild and test failed.\n"
    exit 1
  fi
fi

if [ ${RUN_INTEGRATION} -eq 1 ] || [ ${TF_ACCOUNT_MANAGEMENT} -eq 1 ]; then
  build_and_test_exit_code=0
  if [[ ${RUN_INTEGRATION} -eq 1 ]]; then
      set +e
      run-integration-tests
      build_and_test_exit_code=$?
      set -e
  fi
fi

record_timings "auth api pre-commit total" auth_api_pre_commit_start_seconds $SECONDS true

printf "\nauth api pre-commit task timings:\n\n"
for i in "${task_timings[@]}"; do echo "$i"; done
printf "\n"

if [ ${build_and_test_exit_code} -ne 0 ]; then
  printf "\npre-commit failed.\n"
  exit ${build_and_test_exit_code}
else
  if [[ ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_success
  fi
fi
