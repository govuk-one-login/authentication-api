# di-authentication-api

This repo contains the backend code and infrastructure for the Authentication and Orchestration components for [GOV.UK One Login](https://sign-in.service.gov.uk/).

## Documentation:

High level sequence diagrams outlining different journeys can be found in [Diagrams](./docs/diagrams).

### Orchestration Documentation:

Documentation for the Orchestration component can be found in the [Orchestration README](./docs/orchestration/README.md).

## Running the tests

### Unit:

To run the unit test in this repo, run the following command:

```shell script
./gradlew --parallel test jacocoTestReport -x integration-tests:test -x account-management-integration-tests:test -x delivery-receipts-integration-tests:test
```

### Integration:

To run the integration tests in this repo, you can run the following command

```shell script
./gradlew integration-tests:test
```

If the tests aren't running in `account-management-integration-tests` refer to the [Local Running README](./local-running/README.md) and make sure
you have the correct repositories up to date.

### Contract (Pact):

Contract tests verify that two services agree on the format of their API communication without needing to run them together. They use [Pact](https://docs.pact.io/) to define a shared contract between a **consumer** (the service making requests) and a **provider** (the service handling them).

Most of the contract tests in this repo are **consumer-side** Pact tests. They live in `contract` packages within each module (e.g. `frontend-api/src/test/java/.../contract/`).
For example, the frontend-api is the consumer — it makes outbound requests to external services (TICF CRI, Account Interventions, IPV, etc.).

#### How they work

1. Each test class defines the expected request/response interactions using `@Pact` methods
2. A Pact mock server starts locally and acts as the provider
3. The real handler code runs against the mock server
4. If the handler sends a request matching the pact definition and handles the response correctly, the test passes
5. A **pact file** (JSON) is generated in `<module>/build/pacts/`
6. On merge, the pact file is published to a Pact Broker
7. The provider team runs the pact file against their real service to verify they satisfy the contract

This means both sides can test independently. If either side drifts from the contract, their tests fail.

#### Running contract tests

Run all contract tests for a module:

```shell
./gradlew frontend-api:pactConsumerTests
```

#### Running in IntelliJ

Contract tests are **excluded** from the standard `test` task, so clicking the play button won't work with the default Gradle test runner. Two options:

1. **Change IntelliJ's test runner** — Go to Settings → Build, Execution, Deployment → Build Tools → Gradle → change "Run tests using" to **IntelliJ IDEA**. The play button will then work directly.

2. **Create a Gradle run configuration** — Run → Edit Configurations → + → Gradle. Set the task to `frontend-api:pactConsumerTests` (but this can only run all the tests unless you specify a configuration per test)

#### When to update contract tests

- **Adding a new field to an outbound request** — Add the field to the pact definition if it will be present in the JSON payload
- **Changing the shape of a request/response** — Update the relevant `@Pact` method
- **Adding a new external service interaction** — Create a new test class

#### Important notes

- Null fields stripped during serialization don't need to be in the pact definition.
- The provider team must verify against your updated pact before the change is safe to deploy to production. Ensure you communicate with the team that have the provider tests.
- Pact files are published automatically on merge via CI (requires `PACT_URL`, `PACT_USER`, `PACT_PASSWORD` env vars - see [contract-tests.yaml](.github/workflows/contract-tests.yml)).

## Alarm Management

The `alarm-management.sh` script provides utilities for managing CloudWatch alarms and SNS subscriptions. It allows you to test alarm functionality, manage SNS topic subscriptions, and verify alarm configurations across different environments. The script supports operations like triggering test alarms, subscribing/unsubscribing from SNS topics, and validating alarm states.

```shell
./scripts/test/alarm-management.sh
```

## Pre-commit hook

The repo has config set up for a custom pre-commit hook in `.pre-commit-config.yaml`.
Pre-commit checks include applying formatting, so after the script has run you may see files updated with formatting changes.

To implement the pre-commit hook, you will need to install pre-commit:

```shell script
brew install pre-commit
```

and then set up the hook by running

```shell script
pre-commit install
```

## Formatting:

This repo uses Spotless for its formatting. You run this by running the following command:

```shell
./gradlew spotlessApply
```

## Deployment

### SAM

#### Deployment via GitHub Actions

- Use the following GitHub actions to deploy to specific dev environments
  - [Deploy Account Management](https://github.com/govuk-one-login/authentication-api/actions/workflows/deploy-api-account-management-sp-dev.yml)
  - [Deploy Internal API, External API, IPV API and Delivery Receipts API](https://github.com/govuk-one-login/authentication-api/actions/workflows/deploy-api-modules-sp-dev.yml)
  - [Deploy Account Data](https://github.com/govuk-one-login/authentication-api/actions/workflows/deploy-api-account-data-dev.yml)
  - [Deploy TICF and Account Intervention](https://github.com/govuk-one-login/authentication-api/actions/workflows/deploy-api-modules-sp-stubs-dev.yml)

#### Deployment via script locally

- For a slightly faster deployment (by deploying specific modules), you can use the following script [sam-deploy-authdevs.sh](./sam-deploy-authdevs.sh)
- This can be used to deploy changes to an individual module, rather than the full api

### Terraform

**NOTE**: We are in the process of migrating all of our api modules to SAM

#### Deployment via GitHub Actions

- Similarly to SAM, there is a [GitHub Action](https://github.com/govuk-one-login/authentication-api/actions/workflows/deploy-api-modules-dev.yml) to deploy the authentication-api to the dev env (can't be used for authdevs)
- These will deploy in our old account (`di-auth-development`)

#### Deployment via script locally

- Use the [deploy-authdevs.sh](./deploy-authdevs.sh) to deploy to an authdev
- Make sure to include the `-p` flag
