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

  ./gradlew clean build auditTerraform -x test
  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_started
  else
    printf "\nServices Started!\n"
  fi
}

run-integration-tests() {
  run_integration_tests_start_seconds=$SECONDS
  ./gradlew :integration-tests:test :account-management-integration-tests:test :composeDownForced
  EXIT_CODE=$?
  record_timings "run-integration-tests" $run_integration_tests_start_seconds $SECONDS false
  return ${EXIT_CODE}
}
