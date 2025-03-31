# Orchestration component

The Orchestration component is responsible for maintaining the RP facing **Open ID Connect** API for [GOV.UK One Login](https://sign-in.service.gov.uk/) as well as directing users between different GOV.UK One Login components.

## Diagrams

High level sequence diagrams for the Orchestration component are located [here](../../docs/diagrams/orchestration) and outline the different flows supported by Orchestration.

## Infrastructure:

Most of the infrastructure for the Orchestration component is defined in the [main cloudformation template](../../template.yaml) as well as a small template [snippet for anomaly alerts](../../orchestration-canary-alarms.template.yaml). However, there are still some resources defined in the Terraform (`./ci/terraform/...`).

## Code

The Orchestration codebase is gradually being separated from the Authentication codebase. The Orchestration code is located in the following locations:

- `ipv-api`
- `oidc-api`
- `client-registry-api`
- `doc-checking-app-api`
- Any directory starting with `orchestration-*`

## Testing:

### Unit tests:

To run all the unit tests in the project you can run the following command:

```shell
./gradlew --parallel test -x integration-tests:test -x account-management-integration-tests:test -x delivery-receipts-integration-tests:test
```

However, it may be useful to run the tests in a specific module in the codebase. For example the following command runs the tests in `oidc-api`:

```shell
./gradlew oidc-api:test
```

Alternatively you can run a single test file:

```shell
./gradlew oidc-api:test --tests uk.gov.di.authentication.oidc.lambda.AuthCodeHandlerTest
```

### Integration tests:

To run all the integration tests in the project you can run the following command:

```shell
./gradlew integration-tests:test
```

### Acceptance Tests:

Acceptance tests for Orchestration are stored in the [orchestration-acceptance-tests repository.](https://github.com/govuk-one-login/orchestration-acceptance-tests)

## Deploying to dev:

We currently use a [workflow in GitHub Actions](../../.github/workflows/deploy-orch-dev.yml) to deploy Orchestration to the development environment for manual testing.

## Documentation:

If a lambda has specific documentation, it will live under `docs/<lambdaName>` for example the [Authorisation Handler.](../../oidc-api/docs/AuthorisationHandler.md)

## Useful links:

- OIDC specification: https://openid.net/specs/openid-connect-core-1_0.html
- Technical documentation for GOV.UK One Login: https://docs.sign-in.service.gov.uk/
