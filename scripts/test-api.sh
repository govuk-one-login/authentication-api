#!/usr/bin/env bash

test-api() {

  printf "\n\nRunning api tests...\n"

  pushd ci/terraform/localstack > /dev/null
  apigatewayid="$(terraform output -raw api-gateway-root-id)"
  popd > /dev/null

  url="http://localhost:45678/restapis/${apigatewayid}/local/_user_request_/token"

  curl -i --location --request POST "${url}" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'code=123456789' \
    --data-urlencode 'client_id=test-id' \
    --data-urlencode 'client_secret=test-secret'

  printf "\n\n"

}
