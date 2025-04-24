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

Run Imposter from the command line:

```shell
imposter up -r --engine-type=jvm
```

# Checking Imposter Responses

Here are some httpie requests to see the example responses:

```shell
#########################################################################################################
# GET
#########################################################################################################

# GET 200 responses
http :8080/v1/mfa-methods/one-mfa
http :8080/v1/mfa-methods/two-mfa
http :8080/v1/mfa-methods/get-when-user-with-multiple-mfa-types-primary-sms
http :8080/v1/mfa-methods/get-when-user-with-single-mfa-type-app

# GET 400 error responses
http :8080/v1/mfa-methods/get-when-user-not-found-or-no-match
http :8080/v1/mfa-methods/get-when-new-method-management-api-not-available
http :8080/v1/mfa-methods/get-when-error-retrieving-mfa-methods
http :8080/v1/mfa-methods/get-when-account-management-api-unexpected-error
http :8080/v1/mfa-methods/get-when-invalid-principal-in-request

# GET 401 error response
http :8080/v1/mfa-methods/get-when-invalid-principal

# GET 404 error response
http :8080/v1/mfa-methods/get-when-404-user-not-found-or-no-match

# GET 500 error responses
http :8080/v1/mfa-methods/get-when-500-error-retrieving-mfa-methods
http :8080/v1/mfa-methods/get-when-unexpected-error-creating-mfa-identifier-for-auth-app-mfa-method

#########################################################################################################
# POST
#########################################################################################################

# POST 200 response
http POST :8080/v1/mfa-methods/create-new-mfa-method

# POST 400 responses
http POST :8080/v1/mfa-methods/post-when-request-is-missing-parameters
http POST :8080/v1/mfa-methods/post-when-user-not-found-or-no-match
http POST :8080/v1/mfa-methods/post-when-new-method-management-api-not-available
http POST :8080/v1/mfa-methods/post-when-default-method-already-exists-new-one-cannot-be-created
http POST :8080/v1/mfa-methods/post-when-invalid-otp-code
http POST :8080/v1/mfa-methods/post-when-mfa-method-count-limit-reached
http POST :8080/v1/mfa-methods/post-when-sms-mfa-method-with-same-number-already-exists
http POST :8080/v1/mfa-methods/post-when-auth-app-mfa-already-exists

# POST 401 response
http POST :8080/v1/mfa-methods/post-when-invalid-principal

# POST 404 response
http POST :8080/v1/mfa-methods/post-404-when-user-not-found-or-no-match

# POST 500 response
http POST :8080/v1/mfa-methods/post-when-unexpected-error-creating-mfa-identifier-for-auth-app-mfa-method

#########################################################################################################
# PUT
#########################################################################################################

# PUT 200 responses
http PUT :8080/v1/mfa-methods/put-when-user-with-single-mfa-type-app/id
http PUT :8080/v1/mfa-methods/put-when-user-with-multiple-mfa-types-default-sms/id

# PUT 400 responses
http PUT :8080/v1/mfa-methods/put-when-new-method-management-api-not-available-in-this-environment/id
http PUT :8080/v1/mfa-methods/put-when-request-is-missing-parameters/id
http PUT :8080/v1/mfa-methods/put-when-invalid-otp-code/id
http PUT :8080/v1/mfa-methods/put-when-cannot-change-type-of-mfa-method/id
http PUT :8080/v1/mfa-methods/put-when-cannot-update-a-backup-sms-mfa-method-phone-number/id
http PUT :8080/v1/mfa-methods/put-when-cannot-update-a-backup-sms-mfa-methods-auth-app-credential/id
http PUT :8080/v1/mfa-methods/put-when-cannot-change-priority-of-default-mfa-method/id
http PUT :8080/v1/mfa-methods/put-when-cannot-update-primary-sms-number-to-number-already-in-use-by-backup/id

# PUT 401 responses
http PUT :8080/v1/mfa-methods/put-when-invalid-principal/id

# PUT 404 responses
http PUT :8080/v1/mfa-methods/put-when-user-not-found-or-no-match/id
http PUT :8080/v1/mfa-methods/put-when-mfa-method-not-found/id

# PUT 500 responses
http PUT :8080/v1/mfa-methods/put-when-attempted-to-update-a-backup-mfa-method-without-a-default-present/id
http PUT :8080/v1/mfa-methods/put-when-unexpected-error-creating-mfa-identifier-for-auth-app-mfa-method/id

#########################################################################################################
# DELETE
#########################################################################################################

# DELETE 200 response
http DELETE :8080/v1/mfa-methods/delete-mfa-method/id

# DELETE 400 responses
http DELETE :8080/v1/mfa-methods/delete-when-new-method-management-api-not-available-in-this-environment/id
http DELETE :8080/v1/mfa-methods/delete-when-request-is-missing-parameters/id
http DELETE :8080/v1/mfa-methods/delete-when-cannot-delete-mfa-method-for-non-migrated-user/id

# DELETE 401 responses

http DELETE :8080/v1/mfa-methods/delete-when-invalid-principal/id

# DELETE 404 responses

http DELETE :8080/v1/mfa-methods/delete-when-user-not-found-or-no-match/id
http DELETE :8080/v1/mfa-methods/delete-when-mfa-method-not-found/id

# DELETE 409 responses

http DELETE :8080/v1/mfa-methods/delete-when-cannot-delete-default-priority-mfa-method/id

```
