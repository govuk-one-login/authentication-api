#!/usr/bin/env bash
set -eu

export AWS_ACCESS_KEY_ID="mock-access-key"
export AWS_SECRET_ACCESS_KEY="mock-secret-key"

pushd ci/terraform/oidc >/dev/null
export API_GATEWAY_ID="$(terraform output -raw api_gateway_root_id)"
export API_KEY="$(terraform output -raw frontend_api_key)"
export RESET_PASSWORD_URL="http://localhost:3000/reset-password?code="
popd >/dev/null

echo "API_GATEWAY_ID=$API_GATEWAY_ID;AWS_ACCESS_KEY_ID=BOB;AWS_SECRET_ACCESS_KEY=builder;LOGIN_URI=http://localhost:3000/;API_KEY=$API_KEY;"

