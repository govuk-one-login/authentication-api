#!/usr/bin/env bash

DOCKER_BASE=docker-compose
function wait_for_docker_services() {
  RUNNING=0
  LOOP_COUNT=0
  echo -n "Waiting for service(s) to become healthy ($*) ."
  until [[ ${RUNNING} == $# || ${LOOP_COUNT} == 100 ]]; do
    RUNNING=$(${DOCKER_BASE} ps -q "$@" | xargs docker inspect | jq -rc '[ .[] | select(.State.Health.Status == "healthy")] | length')
    LOOP_COUNT=$((LOOP_COUNT + 1))
    echo -n "."
  done
  if [[ ${LOOP_COUNT} == 100 ]]; then
    echo "FAILED"
    return 1
  fi
  echo " done!"
  return 0
}

function start_docker_services() {
  ${DOCKER_BASE} up --build -d --no-deps --quiet-pull "$@"
}

function stop_docker_services() {
  ${DOCKER_BASE} down --rmi local --remove-orphans
}

function build_docker_service() {
  ${DOCKER_BASE} build --quiet "$@"
}

function startup_docker() {
  build_docker_service "$@"
  start_docker_services "$@"
  wait_for_docker_services "$@"
}

function run_terraform() {
  pushd "$1" >/dev/null
  rm -fr .terraform/ *.tfstate
  terraform init -backend-config=localstack.hcl
  printf "\nRunning terraform apply (quietly - output redirected to terraform.log)...\n"
  set +e
  terraform apply -var-file=localstack.tfvars -auto-approve > terraform.log
  tf_exit_code=$?
  set -e
  if [ ${tf_exit_code} -eq 0 ]; then
    printf "\nTerraform succeeded.\n"
  else
    printf "\nTerraform failed.\n"
    cat terraform.log
    exit 1
  fi
  popd >/dev/null
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
  stop_docker_services aws redis
  printf "\nStarting di-authentication-api...\n"
  ./gradlew clean build -x test
  printf "\nStarting Docker services...\n"
  startup_docker aws redis
  run_terraform ci/terraform/aws
  if [[ ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_started
  else
    printf "\nServices Started!\n"
  fi
}

run-integration-tests() {
  pushd ci/terraform/aws >/dev/null
  export API_GATEWAY_ID="$(terraform output -raw api_gateway_root_id)"
  popd >/dev/null
  ./gradlew integration-tests:test
}
