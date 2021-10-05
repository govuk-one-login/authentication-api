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
#  if [[ ! -z ${SANDPIT+x} && ${SANDPIT} -eq 1 ]]; then
#    printf "\nRunning against sandpit, AWS credentials are required.\n"
#    export TERRAFORM_BACKEND_CONFIG=sandpit.hcl
#    export TERRAFORM_VAR_FILE=sandpit.tfvars
#  else
#    printf "\nRunning against localstack.  Starting Docker services...\n"
#    startup_docker aws redis dynamodb
#    export AWS_ACCESS_KEY_ID="mock-access-key"
#    export AWS_SECRET_ACCESS_KEY="mock-secret-key"
#    export TERRAFORM_BACKEND_CONFIG=localstack.hcl
#    export TERRAFORM_VAR_FILE=localstack.tfvars
#  fi
#
#  run_terraform ci/terraform/shared
#  run_terraform ci/terraform/oidc
#  run_terraform ci/terraform/audit-processors
#  if [[ ! -z ${TF_ACCOUNT_MANAGEMENT+x} && ${TF_ACCOUNT_MANAGEMENT} -eq 1 ]]; then
#    run_terraform ci/terraform/account-management
#  fi

  ./gradlew clean build :account-management-integration-tests:terraformApply -x test
  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_started
  else
    printf "\nServices Started!\n"
  fi
}

run-integration-tests() {
  run_integration_tests_start_seconds=$SECONDS
  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    ./gradlew --no-daemon integration-tests:test
    EXIT_CODE=$?
  else
    ./gradlew integration-tests:test
    EXIT_CODE=$?
  fi
  record_timings "run-integration-tests" $run_integration_tests_start_seconds $SECONDS false
  return ${EXIT_CODE}
}

run-account-management-integration-tests() {
  run_am_integration_tests_start_seconds=$SECONDS
  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    ./gradlew --no-daemon account-management-integration-tests:test
    EXIT_CODE=$?
  else
    ./gradlew account-management-integration-tests:test
    EXIT_CODE=$?
  fi
  record_timings "run-account-management-integration-tests" $run_am_integration_tests_start_seconds $SECONDS false
  return ${EXIT_CODE}
}
