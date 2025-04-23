# OpenAPI specification for the Account Management API

The Auth team provide this API to allow a Users account to be managed.

# Using the Imposter

The configuration files in the mock folder allow Imposter to run a mock version of the API and
provide a variety of responses that demonstrate how the API works for testing purposes.

The `openapi` plugin is configured in `openapi-plugin-config.yaml`.
The OpenAPI spec includes a number of examples that Imposter should serve. To allow the API to be
called normally a custom script is provided that parses the request and selects the appropriate
response based on path parameters. If no match is found the script takes no action and allows Imposter
to look elsewhere for a matching response.

The `rest` plugin is configured in `rest-plugin-config.yaml`.
This plugin allows the examples in the OpenAPI spec to be augmented by additional responses based on
matching the requested resource path. The responses are stored in json files.

# Running Imposter

Imposter can be run from the command line as per the repo's main README.md. If you have issues
running it this way due to not detecting docker correctly the following command may work:

```shell
imposter up -r --engine-type=jvm
```

# Checking Imposter Responses

Here are some httpie requests to see the example responses:

```shell
# GET successful response
http :8080/v1/mfa-methods/one-mfa
http :8080/v1/mfa-methods/two-mfa
http :8080/v1/mfa-methods/user-with-multiple-mfa-types-primary-sms
http :8080/v1/mfa-methods/user-with-single-mfa-type-app

# GET error responses
http :8080/v1/mfa-methods/user-not-found-or-no-match
http :8080/v1/mfa-methods/new-method-management-api-not-available
http :8080/v1/mfa-methods/error-retrieving-mfa-methods
http :8080/v1/mfa-methods/account-management-api-unexpected-error
http :8080/v1/mfa-methods/invalid-principal-in-request
```
