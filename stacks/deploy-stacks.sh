#!/bin/sh
if [[ -z "$AUTH_ENVIRONMENT" ]]; then
    echo "Set AUTH_ENVIRONMENT variable first." 1>&2
    exit 1
fi

aws cloudformation deploy \
    --template-file ./root.yaml \
    --stack-name root \
    --s3-bucket di-auth-stacks \
    --parameter-overrides \
        Environment=$AUTH_ENVIRONMENT \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --tags \
        Product="GOV.UK One Login" \
        System="Authentication" \
        Environment="$AUTH_ENVIRONMENT" \
        Owner="joe.roberts@digital.cabinet-office.gov.uk" \
        Source="https://github.com/alphagov/di-authentication-api/"
