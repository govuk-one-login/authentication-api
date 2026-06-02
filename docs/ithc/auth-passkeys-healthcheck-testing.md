
# Authentication Passkeys Healthcheck Testing

## Accounts and Resources

See [AWS Infrastructure Diagram — Authentication System](https://github.com/govuk-one-login/authentication-api/blob/main/docs/diagrams/aws-infrastructure-diagram.md)

**Only resources changed or created for the Passkey initiative are in scope.**

The solution is normally deployed across two accounts, one containing data stores and keys and the other containing all 
other application resources.

API testing will be done in the development environment where access to the private APIs can be granted.

Resources are prefixed with the name of their environment such as 'staging-xxxx-api'.

| Account Name                  | Account Id   | Environment | Contents                      |
|-------------------------------|--------------|-------------|-------------------------------|
| di-auth-staging               | 758531536632 | staging     | Datastore and KMS Keys        |
| di-authentication-staging     | 851725205974 | staging     | API Gateway, Lambda functions |
| di-authentication-development | 975050272416 | authdev3    | APIs for testing              |
| di-auth-development           | 653994557586 | authdev3    | Datastore for dev APIs        |

### Frontend Routes

The following pages or frontend components were created or changed for Passkeys:

- [amc-service](https://github.com/govuk-one-login/authentication-frontend/tree/main/src/components/amc-service)
- [create-passkey-callback](https://github.com/govuk-one-login/authentication-frontend/tree/main/src/components/create-passkey-callback)
- [create-passkey](https://github.com/govuk-one-login/authentication-frontend/tree/main/src/components/create-passkey)
- [enter-email](https://github.com/govuk-one-login/authentication-frontend/tree/main/src/components/enter-email)

### API Endpoints

- [Internal API](#internal-api-endpoints-in-scope)
- [Account Management API](#account-management-api-endpoints-in-scope)
- [Data API](#data-api-endpoints-in-scope)

### Infrastructure

Lambda functions + roles etc relating this infrastructure are in scope.

#### Internal API

- [/amc-authorize](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/auth/function/amc-authorize.yaml)
- [/amc-callback](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/auth/function/amc-callback.yaml)
- [/.well-known/amc-jwks.json](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/auth/function/amc-jwks.yaml)
- [/start-passkey-assertion](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/auth/function/start-passkey-assertion.yaml)
- [/finish-passkey-assertion](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/auth/function/finish-passkey-assertion.yaml)
- [/userinfo](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/auth/function/auth-userinfo.yaml)

#### Account Management API

- [retrieve passkeys](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/account-management/function/passkeys-retrieve-proxy.yaml)
- [delete passkey](https://github.com/govuk-one-login/authentication-api/blob/main/ci/cloudformation/account-management/function/passkeys-delete-proxy.yaml)

#### Account Data API

All resources in the account data API have been created for Passkeys.

- [Account Data API](https://github.com/govuk-one-login/authentication-api/tree/main/ci/cloudformation/account-data)

## Authentication Passkeys API Testing

API testing will take place in the di-authentication-development and di-auth-development accounts where access to the 
apis has been provided

### Using the ALB to access private APIs

In development environments an ALB is configured to route to private APIs, exposing them for testing.

Valid API keys and tokens may still be required for access.

An extra 'Host' header is required for the routing, for example:
```
curl -X POST \
    -H "Host: <api-id>.execute-api.eu-west-2.amazonaws.com" \
    -H "Content-Type: application/json" \
    -H "x-api-key: <api-key>" \
    -d '{ <jsonbody> }' \
    http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/<env>/<path>
```

API IDs:

| Environment | Internal API | Account Management API | Data API     |
|-------------|--------------|------------------------|--------------|
| authdev3    | `y3s69ubaz5` | `64th13ebx6`           | `5ctgxqnq37` |

### Testing the Internal API

[Open API Spec](https://github.com/govuk-one-login/authentication-api/blob/main/ci/openAPI/AuthInternalApi.yaml)

#### Access Requirements

- API Key only
- No token

Retrieve the API key 'authdev3-di-auth-internal-api-key' from the [AWS Console for di-authentication-development](https://eu-west-2.console.aws.amazon.com/apigateway/main/api-keys/ef8vaw4cjc?api=unselected&region=eu-west-2&url=https%3A%2F%2Feu-west-2.console.aws.amazon.com%2Fapigateway%2Fhome%3Fregion%3Deu-west-2%23).

#### Internal API Endpoints in scope

| Environment | Path                       | Method | ALB Path                                                                                           |
|-------------|----------------------------|--------|----------------------------------------------------------------------------------------------------|
| authdev3    | /amc-authorize             | POST   | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/amc-authorize             |
| authdev3    | /amc-callback              | POST   | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/amc-callback              |
| authdev3    | /.well-known/amc-jwks.json | GET    | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/.well-known/amc-jwks.json |
| authdev3    | /start-passkey-assertion   | POST   | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/start-passkey-assertion   |
| authdev3    | /finish-passkey-assertion  | POST   | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/finish-passkey-assertion  |
| authdev3    | /userinfo                  | GET    | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/userinfo                  |

#### Internal API curl commands

```bash
export ALB_URL="http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3"
export API_KEY="<retrieve from AWS Console - see above>"
export HOST="y3s69ubaz5.execute-api.eu-west-2.amazonaws.com"
export SESSION_ID="<session-id>"
export CLIENT_SESSION_ID="<client-session-id>"
```

##### GET /.well-known/amc-jwks.json

```bash
curl -s -X GET "$ALB_URL/.well-known/amc-jwks.json" \
  -H "Host: $HOST" \
  -H "x-api-key: $API_KEY"
```

##### POST /amc-authorize

```bash
curl -s -X POST "$ALB_URL/amc-authorize" \
  -H "Host: $HOST" \
  -H "x-api-key: $API_KEY" \
  -H "Session-Id: $SESSION_ID" \
  -H "Client-Session-Id: $CLIENT_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{"journeyType": "PASSKEY_CREATE"}'
```

##### POST /amc-callback

```bash
curl -s -X POST "$ALB_URL/amc-callback" \
  -H "Host: $HOST" \
  -H "x-api-key: $API_KEY" \
  -H "Session-Id: $SESSION_ID" \
  -H "Client-Session-Id: $CLIENT_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{"code": "<auth-code>", "state": "<state>", "usedRedirectUrl": "<redirect-url>"}'
```

##### POST /start-passkey-assertion

```bash
curl -s -X POST "$ALB_URL/start-passkey-assertion" \
  -H "Host: $HOST" \
  -H "x-api-key: $API_KEY" \
  -H "Session-Id: $SESSION_ID" \
  -H "Client-Session-Id: $CLIENT_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{}'
```

##### POST /finish-passkey-assertion

```bash
curl -s -X POST "$ALB_URL/finish-passkey-assertion" \
  -H "Host: $HOST" \
  -H "x-api-key: $API_KEY" \
  -H "Session-Id: $SESSION_ID" \
  -H "Client-Session-Id: $CLIENT_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{"pkc": "<public-key-credential-json>"}'
```

##### GET /userinfo

```bash
curl -s -X GET "$ALB_URL/userinfo" \
  -H "Host: $HOST" \
  -H "x-api-key: $API_KEY" \
  -H "Authorization: Bearer <access-token>"
```

### Testing the Account Management API

[Open API Spec](https://github.com/govuk-one-login/authentication-api/blob/main/ci/openAPI/AccountManagementMMApi.yaml)

See [AM API testing using curl](https://github.com/govuk-one-login/authentication-api/blob/main/http/README.md#am-api-testing-using-curl) 

#### Access Requirements

- Access token (from the RP Stub)

#### Account Management API Endpoints in scope

| Environment | Path                                              | Method | ALB Path                                                                                                                    |
|-------------|---------------------------------------------------|--------|-----------------------------------------------------------------------------------------------------------------------------|
| authdev3    | v1/passkeys/{publicSubjectId}                     | GET    | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/v1/passkeys/{publicSubjectId}                      |
| authdev3    | v1/passkeys/{publicSubjectId}/{passkeyIdentifier} | DELETE | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/v1/passkeys/{publicSubjectId}/{passkeyIdentifier}  |


#### Account Management API Passkeys endpoint testing

Using the ALB format.

- Sign in using the [RP Stub](https://rp-dev.build.stubs.account.gov.uk/) changing the Relying Party to `Authdev3`
- Select the 'Account Management' scope checkbox and click 'continue'
- Go through the sign in journey (create an account if required)until you reach the 'User information' page
- The 'Access Token' is used for the AM API
- The "account_data_api_access_token" in 'User Info response' is for both the Data API and the AM API
- The "public_subject_id" in 'User Info response' will be a path parameter when calling the APIs

```bash
export BASE_URL="http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3"
export AUTH_TOKEN="eyJraWQiOiJkM2NlMmM1NTk3OTIyYTg4M2UzYWQ0MzE4YzJlMmM4YWQ1MjFlZjY4NDIyNzY3OWZlNDVjMTVjNGMyZmE3OGFiIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOjI4WVM5VlZyRVNyekkzNGljaWdQdnhuWFFTTDdMUUozaDZlNzJxMFVnQnMiLCJzY29wZSI6WyJvcGVuaWQiLCJlbWFpbCIsInBob25lIiwiYW0iXSwiaXNzIjoiaHR0cHM6Ly9vaWRjLmF1dGhkZXYzLmRldi5hY2NvdW50Lmdvdi51ay8iLCJleHAiOjE3ODA1MDEyMzgsImlhdCI6MTc4MDUwMTA1OCwiY2xpZW50X2lkIjoiZnZXb3B4RUVDb0FoZFU3dVRZcXRGMjhndWVBcGdpb3ciLCJqdGkiOiJiZGU5YzVkNi1jMmQ5LTQ1YzQtYTRjMS1mZjk4NzZlZTFhNDgiLCJzaWQiOiJtZ3VrWDhZUmlaeElGbHlFS3VCQmlxTGNBcGsifQ.M1AjTv-88CL45_2RTxRlI6cPNr8Ykvzu2Q1wTivnmzsrX9iRD2bnQDnkpteTFnGeGJ9yjXfwqug8HVaFXL27LQ"
export PUBLIC_SUBJECT_ID="-deRzccLWy8DTp8mWVv5GkEhAVUb-UvZWXb0GrcQmpA"
export PASSKEY_ID="your-passkey-identifier"
export ADAPI_TOKEN="eyJraWQiOiI1YTQ1ZTFmZmIwZDgxYzhjMTM1YTM0ZTIxYjc1N2JiZTc0Mjg1MTU1ZDYwMzUzODI2YWRhNjNiNDQ5YzNmNGQxIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJodHRwczovL2FjY291bnQuYXV0aGRldjMuZGV2LmFjY291bnQuZ292LnVrIiwic3ViIjoiLWRlUnpjY0xXeThEVHA4bVdWdjVHa0VoQVZVYi1VdlpXWGIwR3JjUW1wQSIsIm5iZiI6MTc4MDUwMDE1MSwic2NvcGUiOiJwYXNza2V5LWNyZWF0ZSBwYXNza2V5LXJldHJpZXZlIHBhc3NrZXktdXBkYXRlIHBhc3NrZXktZGVsZXRlIiwiaXNzIjoiaHR0cHM6Ly9zaWduaW4uYXV0aGRldjMuZGV2LmFjY291bnQuZ292LnVrIiwiZXhwIjoxNzgwNTA3MzUxLCJpYXQiOjE3ODA1MDAxNTEsImNsaWVudF9pZCI6ImhvbWUiLCJqdGkiOiIwMTY3ZTNlZi1hYWE2LTRmMDktYTVmYS1mMjkzZDg3MDJmOTMiLCJzaWQiOiI2WnNpWGFra2NmS2JwT3k1WkJFMkFJbnJfb2sifQ.VL7pxjuOJEVGk135769jqHSJONEv2dcZfx0vSQNB09IiI69GlVNTasZgEKl4ec8snytYqnpRG3e4NoOQga7qKA"
```

##### Retrieve Passkeys

```bash
curl -X GET "$BASE_URL/v1/passkeys/$PUBLIC_SUBJECT_ID" \
    -H "Host: 64th13ebx6.execute-api.eu-west-2.amazonaws.com" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-ADAPI-AccessToken: $ADAPI_TOKEN"
```

##### Delete Passkey

```bash
curl -X DELETE "$BASE_URL/v1/passkeys/$PUBLIC_SUBJECT_ID/$PASSKEY_ID" \
    -H "Host: 64th13ebx6.execute-api.eu-west-2.amazonaws.com" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-ADAPI-AccessToken: $ADAPI_TOKEN"
```

### Testing the Data API

[Open API Spec](https://github.com/govuk-one-login/authentication-api/blob/main/ci/openAPI/AccountDataApi.yaml)

#### Access Requirements

You need a valid token, either by running the script (see [Generating a token](#generating-a-token-for-cloudshell-or-authorizer-lambda-testing-only))
and a `Host` header for routing, or by logging in to the [Authdev 3 RP Stub](https://rp-dev.build.stubs.account.gov.uk/).

#### Data API Endpoints in scope

| Environment | Path                                                            | Method | ALB Path                                                                                                                                |
|-------------|-----------------------------------------------------------------|--------|-----------------------------------------------------------------------------------------------------------------------------------------|
| authdev3    | /accounts/{publicSubjectId}/authenticators/passkeys             | GET    | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/accounts/{publicSubjectId}/authenticators/passkeys             |
| authdev3    | /accounts/{publicSubjectId}/authenticators/passkeys             | POST   | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/accounts/{publicSubjectId}/authenticators/passkeys             |
| authdev3    | /accounts/{publicSubjectId}/authenticators/passkeys/{passkeyId} | DELETE | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/accounts/{publicSubjectId}/authenticators/passkeys/{passkeyId} |
| authdev3    | /accounts/{publicSubjectId}/authenticators/passkeys/{passkeyId} | PATCH  | http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com/authdev3/accounts/{publicSubjectId}/authenticators/passkeys/{passkeyId} |

#### Testing via ALB (development environments)

In development environments an ALB is configured to route to private APIs.

- Sign in using the [RP Stub](https://rp-dev.build.stubs.account.gov.uk/) changing the Relying Party to `Authdev3`
- Select the 'Account Management' scope checkbox and click 'continue'
- Go through the sign in journey (create an account if required) until you reach the 'User information' page
- The 'Access Token' is used for the AM API
- The "account_data_api_access_token" in 'User Info response' is for both the Data API and the AM API
- The "public_subject_id" in 'User Info response' will be a path parameter when calling the APIs

```bash
export PUBLIC_SUBJECT_ID="-deRzccLWy8DTp8mWVv5GkEhAVUb-UvZWXb0GrcQmpA"
export PASSKEY_ID="1234-5678"
export API_ID="5ctgxqnq37"
export ENVIRONMENT="authdev3"
export ALB_URL="http://auth-test-alb-alb-1869347301.eu-west-2.elb.amazonaws.com"
export AD_API_TOKEN="<from account_data_api_access_token>"
```

#### Retrieve passkeys

```bash
curl -s -X GET \
  "$ALB_URL/$ENVIRONMENT/accounts/$PUBLIC_SUBJECT_ID/authenticators/passkeys" \
  -H "Host: $API_ID.execute-api.eu-west-2.amazonaws.com" \
  -H "Authorization: Bearer $AD_API_TOKEN"
```

#### Create a passkey

```bash
curl -s -X POST \
  "$ALB_URL/$ENVIRONMENT/accounts/$PUBLIC_SUBJECT_ID/authenticators/passkeys" \
  -H "Host: $API_ID.execute-api.eu-west-2.amazonaws.com" \
  -H "Authorization: Bearer $AD_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credential":"credential","id":"'$PASSKEY_ID'","aaguid":"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4","isAttested":"false","signCount":"0","transports":["internal","hybrid"],"isBackedUpEligible":"false","isBackedUp":"false","isResidentKey":"false"}'
```

#### Update a passkey

```bash
curl -s -X PATCH \
  "$ALB_URL/$ENVIRONMENT/accounts/$PUBLIC_SUBJECT_ID/authenticators/passkeys/$PASSKEY_ID" \
  -H "Host: $API_ID.execute-api.eu-west-2.amazonaws.com" \
  -H "Authorization: Bearer $AD_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"signCount": 1, "lastUsedAt": "2026-06-03T16:00:00Z"}'
```

#### Delete a passkey

```bash
curl -s -X DELETE \
  "$ALB_URL/$ENVIRONMENT/accounts/$PUBLIC_SUBJECT_ID/authenticators/passkeys/$PASSKEY_ID" \
  -H "Host: $API_ID.execute-api.eu-west-2.amazonaws.com" \
  -H "Authorization: Bearer $AD_API_TOKEN"
```
