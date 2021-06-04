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
  pushd $1 >/dev/null
  rm -f terraform.tfstate
  rm -f terraform.tfstate.backup
  terraform init
  terraform apply -auto-approve
  tf_exit_code=$?
  if [ ${tf_exit_code} -ne 0 ]; then
    printf "\nTerraform failed.\n"
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
  stop_docker_services aws
  printf "\nStarting di-authentication-api...\n"
  ./gradlew clean build -x test
  printf "\nStarting Docker services...\n"
  startup_docker aws
  run_terraform ci/terraform/localstack
  funky_started
}

run-integration-tests() {
  pushd ci/terraform/localstack >/dev/null
  export API_GATEWAY_ID="$(terraform output -raw api-gateway-root-id)"
  popd >/dev/null
  ./gradlew integration-tests:test
}
