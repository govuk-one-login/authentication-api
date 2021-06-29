#!/usr/bin/env bash

test-api() {

  printf "\n\nRunning api tests...\n"

  pushd ci/terraform/localstack > /dev/null
  url="$(terraform output -raw base_url)"
  popd > /dev/null

  curl -i --location --request POST "${url}/token" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'code=123456789' \
    --data-urlencode 'client_id=test-id' \
    --data-urlencode 'client_secret=test-secret'

  printf "\n\n"

}
