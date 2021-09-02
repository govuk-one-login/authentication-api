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
  printf "\nRunning terraform -> %s apply quietly (output redirected to terraform.log)...\n" "$1"
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
  tput setaf 2g
  cat scripts/started.txt
  tput sgr0
}

startup() {
  export TF_VAR_notify_url="http://notify.internal:8888"
  export TF_VAR_notify_api_key="my_test_key-$(uuidgen)-$(uuidgen)"
  export AWS_ACCESS_KEY_ID="mock-access-key"
  export AWS_SECRET_ACCESS_KEY="mock-secret-key"
  export STUB_RELYING_PARTY_REDIRECT_URI="https://di-auth-stub-relying-party-build.london.cloudapps.digital/"
  export LOGIN_URI="http://localhost:3000/"

  stop_docker_services aws redis dynamodb
  printf "\nStarting di-authentication-api...\n"
  ./gradlew clean build -x test
  printf "\nStarting Docker services...\n"
  startup_docker aws redis dynamodb
  run_terraform ci/terraform/oidc
  if [[ ! -z ${TF_ACCOUNT_MANAGEMENT+x} && ${TF_ACCOUNT_MANAGEMENT} -eq 1 ]]; then
    run_terraform ci/terraform/account-management
  fi
  if [[ -z ${IN_GITHUB_ACTIONS+x} ||  ${IN_GITHUB_ACTIONS} -eq 0 ]]; then
    funky_started
  else
    printf "\nServices Started!\n"
  fi
}

run-integration-tests() {
  pushd ci/terraform/oidc >/dev/null
  export API_GATEWAY_ID="$(terraform output -raw api_gateway_root_id)"
  export TOKEN_SIGNING_KEY_ID="$(terraform output -raw token_signing_key_id)"
  export BASE_URL="$(terraform output -raw base_url)"
  popd >/dev/null
  ./gradlew integration-tests:test
}

run-account-management-integration-tests() {
  pushd ci/terraform/account-management >/dev/null
  export API_GATEWAY_ID="$(terraform output -raw api_gateway_root_id)"
  export BASE_URL="$(terraform output -raw base_url)"
  popd >/dev/null
  ./gradlew account-management-integration-tests:test
}
