# OpenAPI specification for the Frontend API

The Auth team provides this API to allow frontend applications to interact with the authentication service.

This API specification documents the endpoints available for frontend applications to:
- Start authentication journeys
- Perform user sign-up and login
- Handle MFA verification
- Manage user profiles
- Process password resets
- Handle account recovery
- Interact with ID verification services

## API Documentation

The OpenAPI specification in this directory provides a complete reference for all endpoints, request/response formats, and error codes.

## Testing the Frontend API

The API can be tested using standard HTTP clients. Example requests for key endpoints:

```shell
# Start a new authentication journey
http POST :8080/start

# Check if a user exists
http POST :8080/user-exists

# Sign up a new user
http POST :8080/signup

# Login with credentials
http POST :8080/login

# Verify MFA code
http POST :8080/verify-code

# Reset password
http POST :8080/reset-password-request
```