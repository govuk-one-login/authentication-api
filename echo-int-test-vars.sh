#!/usr/bin/env bash
set -euo pipefail

export AWS_ACCESS_KEY_ID="mockaccesskey"
export AWS_SECRET_ACCESS_KEY="mocksecretkey"

pushd ci/terraform/oidc > /dev/null
API_GATEWAY_ID="$(terraform output -raw api_gateway_root_id)"
export API_GATEWAY_ID
API_KEY="$(terraform output -raw di-auth-frontend-api-key)"
export API_KEY
FRONTEND_API_GATEWAY_ID="$(terraform output -raw frontend_api_gateway_root_id)"
export FRONTEND_API_GATEWAY_ID
FRONTEND_API_KEY="$(terraform output -raw frontend_api_key)"
export FRONTEND_API_KEY
export RESET_PASSWORD_URL="http://localhost:3000/reset-password?code="
export STUB_RELYING_PARTY_REDIRECT_URI="https://rp-build.build.stubs.account.gov.uk/"
popd > /dev/null

echo "API_GATEWAY_ID=$API_GATEWAY_ID;AWS_ACCESS_KEY_ID=BOB;AWS_SECRET_ACCESS_KEY=builder;LOGIN_URI=http://localhost:3000/;API_KEY=$API_KEY;FRONTEND_API_GATEWAY_ID=$FRONTEND_API_GATEWAY_ID;FRONTEND_API_KEY=$FRONTEND_API_KEY;STUB_RELYING_PARTY_REDIRECT_URI=$STUB_RELYING_PARTY_REDIRECT_URI;"
