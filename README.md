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
