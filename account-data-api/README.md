# account-data-api

## Testing changes in dev environments

The API is private (VPC-only) and cannot be called directly from your machine. Instead, invoke the Lambda functions directly via the AWS CLI — this bypasses API Gateway and the authorizer, so you control the full event payload.

The API Gateway console's Test tab is also not suitable here: it skips the authorizer entirely and never populates `requestContext.authorizer`, which means the handlers will always return 401 since they require `principalId` to be present.

Unlike the account-management API, which has a dedicated nginx proxy EC2 instance accessible via SSM port forwarding (see `scripts/api-proxy.sh`), the account-data API has no such proxy. Direct Lambda invocation is simpler to set up and sufficient for most testing. If you find yourself needing to test the full request flow including the authorizer and API Gateway behaviour (e.g. testing resource policies, authorizer caching, or request/response mapping), it would be worth adding a similar proxy setup — see `ci/terraform/account-management/mm-api-dev-access.tf` for the pattern.

### Prerequisites

- You have access to a profile with api invoke permissions (e.g. admin)
- AWS SSO authenticated: `aws sso login --profile <profile>`

### Generating a token

If you need a valid signed token (e.g. to test the authorizer in isolation via the console), use the token generation script.
You will need to retrieve the kms id from aws. Note that currently these other claims can be anything - future validation
will make this more strict.

```bash
export AUTH_TO_ACCOUNT_DATA_SIGNING_KEY=<kms-key-id>
export AUTH_TO_ACCOUNT_DATA_API_AUDIENCE=<audience>
export AUTH_ISSUER_CLAIM=<issuer>
export AMC_CLIENT_ID=<client-id>

python3 ./account-data-api/scripts/generate_account_data_token.py <public-subject-id> --profile <profile> --region <aws region>
```

### Invoking Lambda functions directly

When invoking Lambda directly you must supply `pathParameters` and `requestContext.authorizer.principalId` explicitly — API Gateway is not involved so these are not populated automatically.

The `principalId` must match the `publicSubjectId` path parameter, otherwise the handler returns 401.

#### Retrieve passkeys

```bash
aws lambda invoke \
  --function-name <env>-account-data-passkeys-retrieve-lambda \
  --cli-binary-format raw-in-base64-out \
  --profile <profile> \
  --region eu-west-2 \
  --payload '{
    "httpMethod": "GET",
    "pathParameters": {"publicSubjectId": "<subject-id>"},
    "requestContext": {"authorizer": {"principalId": "<subject-id>"}}
  }' \
  response.json && cat response.json
```

#### Create a passkey

```bash
aws lambda invoke \
  --function-name <env>-account-data-passkeys-create-lambda \
  --cli-binary-format raw-in-base64-out \
  --profile <profile> \
  --region eu-west-2 \
  --payload '{
    "httpMethod": "POST",
    "pathParameters": {"publicSubjectId": "<subject-id>"},
    "requestContext": {"authorizer": {"principalId": "<subject-id>"}},
    "body": "{\"credential\":\"credential\",\"id\":\"<passkey-id>\",\"aaguid\":\"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4\",\"isAttested\":\"false\",\"signCount\":\"0\",\"transports\":[\"internal\",\"hybrid\"],\"isBackedUpEligible\":\"false\",\"isBackedUp\":\"false\",\"isResidentKey\":\"false\"}"
  }' \
  response.json && cat response.json
```

#### Update a passkey

```bash
aws lambda invoke \
  --function-name <env>-account-data-passkeys-update-lambda \
  --cli-binary-format raw-in-base64-out \
  --profile <profile> \
  --region eu-west-2 \
  --payload '{
    "httpMethod": "PATCH",
    "pathParameters": {"publicSubjectId": "<subject-id>", "passkeyId": "<passkey-id>"},
    "requestContext": {"authorizer": {"principalId": "<subject-id>"}},
    "body": "{\"signCount\": 1, \"lastUsedAt\": \"2026-05-11T14:00:00Z\"}"
  }' \
  response.json && cat response.json
```

#### Delete a passkey

```bash
aws lambda invoke \
  --function-name <env>-account-data-passkeys-delete-lambda \
  --cli-binary-format raw-in-base64-out \
  --profile <profile> \
  --region eu-west-2 \
  --payload '{
    "httpMethod": "DELETE",
    "pathParameters": {"publicSubjectId": "<subject-id>", "passkeyId": "<passkey-id>"},
    "requestContext": {"authorizer": {"principalId": "<subject-id>"}}
  }' \
  response.json && cat response.json
```

Replace `<env>` with e.g. `authdev1`, `<profile>` with e.g. `authdev1-admin`, and `<subject-id>`/`<passkey-id>` with the relevant values for your case.
