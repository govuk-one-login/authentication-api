# account-management-api

The account management API provides an interface for the Home team to interact with the authentication service, accessing
and making changes to user data.

For the Home service to access or make changes to user data, they must first go through an OAUTH flow
to receive an access token. This bearer token is passed in the headers when making a request. The bearer token is processed
by the AuthoriseAccessTokenHandler lambda. If successful, the request is forwarded to the lambda associated with the path
requested.

# Testing the Account Management API

The API can be manually tested using the http/account-management.http file. Instructions are contained in the file.
