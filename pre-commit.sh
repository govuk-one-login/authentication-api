#!/usr/bin/env bash

source ./scripts/functions.sh
source ./scripts/test-api.sh

printf "\nRunning build and unit tests...\n"

./gradlew clean build

build_and_test_exit_code=$?
if [ ${build_and_test_exit_code} -ne 0 ]; then
  printf "\nBuild and test failed.\n"
  exit 1
fi

startup
test-api

build_and_test_exit_code=$?

stop_docker_services aws

if [ ${build_and_test_exit_code} -ne 0 ]; then
  printf "\npre-commit failed.\n"
else
  funky_success
fi
