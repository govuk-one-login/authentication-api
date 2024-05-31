#!/usr/bin/env bash
set -euo pipefail

export AWS_PAGER=""

function loginAws() {
  export AWS_REGION=us-east-1
  case $1 in
  dev)
    export AWS_PROFILE=gds-di-development-admin
    ;;
  build)
    export AWS_PROFILE=gds-di-development-admin
    ;;
  staging)
    export AWS_PROFILE=di-auth-staging-admin
    ;;
  integration)
    export AWS_PROFILE=gds-di-development-admin
    ;;
  production)
    export AWS_PROFILE=gds-di-production-admin
    ;;
  esac

  # shellcheck disable=SC1091
  source "../../../scripts/export_aws_creds.sh"
}

PERMITTED_ENVIRONMENTS="dev build staging integration production"

if  [[ $# == 0 ]] || ! [[ $PERMITTED_ENVIRONMENTS =~ ( |^)$1( |$) ]]; then
  echo "Call ./deploy <env>, where <env> is one of $PERMITTED_ENVIRONMENTS"
  exit 1
fi

ENVIRONMENT=$1

PARAMETERS_FILE=${PARAMETERS_FILE:=./$ENVIRONMENT/parameters.json}
TAGS_FILE=${TAGS_FILE:=./$ENVIRONMENT/tags.json}

if  [ ! -f "$PARAMETERS_FILE" ]; then
  echo "Configuration file not found. Please see README.md"
  exit 1
fi

if  [ ! -f "$TAGS_FILE" ]; then
  echo "Tags file not found. Please see README.md"
  exit 1
fi

loginAws "$ENVIRONMENT"

if [[ $ENVIRONMENT == dev ]]; then
  SMOKETEST_CLIENT_ID=$(aws ssm get-parameter --name sandpit-smoke-in-client-id | jq --raw-output .Parameter.Value)
  PARAMETERS=$(jq ". += [{\"ParameterKey\":\"SmokeTestClientId\",\"ParameterValue\":\"${SMOKETEST_CLIENT_ID}\"}] | tojson" -r "${PARAMETERS_FILE}")
elif [[ $ENVIRONMENT == production ]]; then
  SMOKETEST_CLIENT_ID=$(aws ssm get-parameter --name production-smoke-in-client-id | jq --raw-output .Parameter.Value)
  PARAMETERS=$(jq ". += [{\"ParameterKey\":\"SmokeTestClientId\",\"ParameterValue\":\"${SMOKETEST_CLIENT_ID}\"}] | tojson" -r "${PARAMETERS_FILE}")
else
  PARAMETERS=$(jq '. | tojson' -r "${PARAMETERS_FILE}")
fi

if [[ $# == 2 ]] && [[ $2 == "--create" ]]; then
  aws cloudformation create-stack \
      --region us-east-1 \
      --enable-termination-protection \
      --stack-name="$ENVIRONMENT-oidc-cloudfront-waf" \
      --template-body file://template.yaml \
      --parameters="$PARAMETERS" \
      --tags="$(jq '. | tojson' -r "${TAGS_FILE}")"
else
    aws cloudformation update-stack \
        --region us-east-1 \
        --stack-name="$ENVIRONMENT-oidc-cloudfront-waf" \
        --template-body file://template.yaml \
        --parameters="$PARAMETERS" \
        --tags="$(jq '. | tojson' -r "${TAGS_FILE}")"
fi
