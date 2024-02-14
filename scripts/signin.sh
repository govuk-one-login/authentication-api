#!/usr/bin/env bash

set -eu

rm -f login-cookies.txt

echo "/authorize"
csrf=""

csrf=$(curl "https://oidc.build.account.gov.uk/authorize?vtr=%5B%22Cl.Cm%22%5D&scope=openid+email+phone&claims=%7B%22userinfo%22%3A%7B%22https%3A%5C%2F%5C%2Fvocab.account.gov.uk%5C%2Fv1%5C%2Fpassport%22%3A%7B%22essential%22%3Atrue%7D%2C%22https%3A%5C%2F%5C%2Fvocab.account.gov.uk%5C%2Fv1%5C%2FcoreIdentityJWT%22%3A%7B%22essential%22%3Atrue%7D%2C%22https%3A%5C%2F%5C%2Fvocab.account.gov.uk%5C%2Fv1%5C%2Faddress%22%3A%7B%22essential%22%3Atrue%7D%7D%7D&response_type=code&redirect_uri=https%3A%2F%2Fdi-auth-stub-relying-party-build.london.cloudapps.digital%2Foidc%2Fauthorization-code%2Fcallback&state=XPiTXQ7EjaYADvToEDuWnMPfchpcJCPOhqqp1eeNqK4&prompt=none&nonce=7DCU3c1sZTQn7dWOlPlri9HDSy0Z2t6XhlV5vR6xCc8&client_id=k1c4gClyIxZtbeWm6dOXQ2RDrN4GBj3X" \
  -L \
  -c login-cookies.txt |
  grep "_csrf" | sed "s/.* value=\"\(.*\)\".*/\1/")

echo "/sign-in-or-create"
echo $csrf

page=$(
  curl -X POST "https://signin.build.account.gov.uk/sign-in-or-create" \
    -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' \
    -L \
    -c login-cookies.txt \
    -F '_csrf=$csrf' \
    -F 'supportInternationalNumbers=true' \
    --compressed
)

echo $page
