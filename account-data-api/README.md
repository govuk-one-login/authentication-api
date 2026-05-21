# account-data-api

## Testing changes in dev environments

The API is private (VPC-only) and cannot be called directly from your machine. The API Gateway console's Test tab is also not suitable here: it skips the authorizer entirely and never populates `requestContext.authorizer`, which means the handlers will always return 401 since they require `principalId` to be present.

You can either use CloudShell in a VPC environment (which goes through the full API Gateway flow including the authorizer) or invoke Lambda functions directly via the AWS CLI (which bypasses API Gateway).

### Prerequisites

- You have access to a profile with api invoke permissions (e.g. admin)
- AWS SSO authenticated: `aws sso login --profile <profile>`

### Generating a token (for CloudShell or Authorizer lambda testing only)

Use the token generation script to create a valid signed JWT. This is only needed when testing via CloudShell (full API Gateway flow) or invoking the authorizer lambda directly. When invoking endpoint Lambdas directly, you control the authorizer context in the payload and don't need a real token.

Requires Python 3 and `boto3`:

```bash
pip install boto3
```

#### Environment variables (authdev1 example)

```bash
export AUTH_TO_ACCOUNT_DATA_SIGNING_KEY="alias/authdev1-auth-to-account-data-signing-key"
export AUTH_TO_ACCOUNT_DATA_API_AUDIENCE="https://account.authdev1.dev.account.gov.uk"
export AUTH_ISSUER_CLAIM="https://signin.authdev1.dev.account.gov.uk"
export AMC_CLIENT_ID="auth"
```

#### Generate a token

```bash
python3 ./account-data-api/scripts/generate_account_data_token.py <public-subject-id> \
  --scope "passkey-create passkey-retrieve" \
  --profile di-authentication-development-AdministratorAccessPermission
```

Available scopes: `passkey-create`, `passkey-retrieve`, `passkey-update`, `passkey-delete`

Multiple scopes can be passed as a space-separated string (e.g. `"passkey-create passkey-retrieve"`).

Options: `--ttl <minutes>` (default 5), `--region <region>` (default eu-west-2)

### Testing via CloudShell (full API Gateway flow)

The API Gateway Console Test tab does not invoke the custom authorizer. To test the full flow (authorizer → handler), use CloudShell in a VPC environment.

#### Setting up the CloudShell VPC session

1. Open CloudShell in the AWS Console
2. Start a VPC environment with:
   - **VPC**: `vpc-Vpc` (not the Control Tower VPC)
   - **Subnet**: any subnet
   - **Security group**: any that allows outbound on port 443 (e.g. `authentication-api-HttpsEgressSecurityGroup`)

#### Making a request

```bash
curl -s -H "Authorization: Bearer <token>" \
  "https://<api-id>.execute-api.eu-west-2.amazonaws.com/<env>/accounts/<public-subject-id>/authenticators/passkeys" | jq
```

API IDs:

| Environment | API ID       |
| ----------- | ------------ |
| authdev1    | `rjlo8fsb55` |
| authdev2    | `ez2ro7vca7` |
| authdev3    | `5ctgxqnq37` |
| dev         | `0aqzty84lj` |

### Invoking the authorizer Lambda directly

You can test the authorizer in isolation by invoking it with a TOKEN event. This requires a valid signed token (see [Generating a token](#generating-a-token-for-cloudshell-testing-only)).

```bash
aws lambda invoke \
  --function-name <env>-account-data-authorizer-lambda \
  --cli-binary-format raw-in-base64-out \
  --profile <profile> \
  --region eu-west-2 \
  --payload '{
    "type": "TOKEN",
    "authorizationToken": "Bearer <token>",
    "methodArn": "arn:aws:execute-api:eu-west-2:975050272416:<api-id>/<env>/GET/accounts/{publicSubjectId}/authenticators/passkeys"
  }' \
  response.json && cat response.json
```

A valid token returns an Allow policy with the scope in context. An invalid token throws `UnauthorizedException`.

### Invoking handler Lambda functions directly

When invoking Lambda directly you must supply `pathParameters` and `requestContext.authorizer.principalId` explicitly — API Gateway is not involved so these are not populated automatically.

The `principalId` must match the `publicSubjectId` path parameter, otherwise the handler returns 401.

The `scope` field should be a space-separated string of the scopes the token was issued with (e.g. `"passkey-create passkey-retrieve"`). Each handler checks that its required scope is present in this list.

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
    "requestContext": {"authorizer": {"principalId": "<subject-id>", "scope": "passkey-retrieve"}}
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
    "requestContext": {"authorizer": {"principalId": "<subject-id>", "scope": "passkey-create"}},
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
    "requestContext": {"authorizer": {"principalId": "<subject-id>", "scope": "passkey-update"}},
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
    "requestContext": {"authorizer": {"principalId": "<subject-id>", "scope": "passkey-delete"}}
  }' \
  response.json && cat response.json
```

Replace `<env>` with e.g. `authdev1`, `<profile>` with e.g. `authdev1-admin`, and `<subject-id>`/`<passkey-id>` with the relevant values for your case.
