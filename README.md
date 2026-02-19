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
