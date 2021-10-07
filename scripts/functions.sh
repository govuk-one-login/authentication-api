#!/usr/bin/env bash

DOCKER_BASE=docker-compose
TF_COMMAND=apply
declare -a task_timings

function record_timings() {
  if [ "$4" = "true" ]; then
    total=$(printf '\t%s' "===================================")
    task_timings+=("$total");
  fi;
  message=$(printf '\t%ss \t\t%s' "$(($3 - $2))" "$1")
  task_timings+=("$message")
}

function funky_success() {
  printf "\nAll is fine...\n"
  tput setaf 2
  cat scripts/now-push.txt
  tput sgr0
}

function funky_started() {
  tput setaf 2
  cat scripts/started.txt
  tput sgr0
}

startup() {
  printf "\nStarting di-authentication-api...\n"

  ./gradlew clean build :account-management-integration-tests:terraformApply -x test
  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_started
  else
    printf "\nServices Started!\n"
  fi
}

run-integration-tests() {
  run_integration_tests_start_seconds=$SECONDS
  TEST_ENVIRONMENT=localstack
  if [[ ! -z ${SANDPIT+x} && ${SANDPIT} -eq 1 ]]; then
    printf "\nRunning against sandpit, AWS credentials are required.\n"
    TEST_ENVIRONMENT=sandpit
  else
    printf "\nRunning against localstack.  Starting Docker services...\n"
  fi

  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    ./gradlew --no-daemon integration-tests:test -PterraformEnvironment=${TEST_ENVIRONMENT}
    EXIT_CODE=$?
  else
    ./gradlew integration-tests:test -PterraformEnvironment=${TEST_ENVIRONMENT}
    EXIT_CODE=$?
  fi
  record_timings "run-integration-tests" $run_integration_tests_start_seconds $SECONDS false
  return ${EXIT_CODE}
}

run-account-management-integration-tests() {
  run_am_integration_tests_start_seconds=$SECONDS
  if [[ ! -z ${SANDPIT+x} && ${SANDPIT} -eq 1 ]]; then
    printf "\nRunning against sandpit, AWS credentials are required.\n"
    TEST_ENVIRONMENT=sandpit
  else
    printf "\nRunning against localstack.  Starting Docker services...\n"
  fi

  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    ./gradlew --no-daemon account-management-integration-tests:test -PterraformEnvironment=${TEST_ENVIRONMENT}
    EXIT_CODE=$?
  else
    ./gradlew account-management-integration-tests:test -PterraformEnvironment=${TEST_ENVIRONMENT}
    EXIT_CODE=$?
  fi
  record_timings "run-account-management-integration-tests" $run_am_integration_tests_start_seconds $SECONDS false
  return ${EXIT_CODE}
}
