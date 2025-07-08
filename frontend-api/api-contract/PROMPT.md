Create a complete OpenAPI specification and mock API setup for the frontend-api that accurately reflects the Java implementation. Use the account-management-api as a reference and ensure all error codes match those defined in the ErrorResponse enum.

1. Create an OpenAPI 3.0.3 specification for the frontend-api with the following components:
   - Basic API information (title, description, version, contact)
   - Server configurations for different environments (build, staging, integration, production)
   - Security schemes (Bearer authentication)
   - Schema definitions for all request and response objects with proper types (Error schema should use integer type for code)
   - Path definitions for all API endpoints including:
     - /start: Initiate authentication journey
     - /user-exists: Check if a user exists
     - /signup: Register a new user
     - /login: Authenticate a user
     - /mfa: Get MFA options
     - /verify-code: Verify MFA code
     - /reset-password-request: Request password reset
     - /reset-password: Complete password reset
     - /account-recovery: Recover account
     - /update-profile: Update user profile

2. For each endpoint in the OpenAPI specification, add detailed examples for all response types:
    - 200 responses: Include realistic success examples with all relevant fields
    - 400 responses: Include examples for all validation errors with correct error codes:
      - Missing parameters (1001)
      - Empty email address (1003)
      - Invalid email format (1004)
      - Empty password (1005)
      - Invalid password format (1006, 1007)
      - Client not found (1015)
      - Invalid redirect URI (1016)
    - 401 responses: Include examples for authentication errors with correct error codes:
      - Invalid login credentials (1008)
      - Session invalid or expired (1000)
      - Account locked (1045)
    - 409 responses: Include examples for conflict errors with correct error codes:
      - Account already exists (1009)
    - 500 responses: Use the appropriate error code (typically 1000) for server errors

3. Create a mock folder structure with the following files:
    - .imposter.yaml: Pin the Imposter version to 3.28.3
    - openapi-plugin-config.yaml: Configure to use the OpenAPI spec with the following settings:
      - specFile: "openapi.yaml"
      - validateRequest: true
      - validateResponse: true
      - respondWithExamples: true
    - respond-with-examples-from-spec.groovy: Script to return examples from the spec
    - rest-plugin-config.yaml: Define REST endpoints for all API paths with appropriate methods and status codes

4. For each endpoint, create JSON mock response files with the correct error codes and messages:
    - Success responses (e.g., login-success.json, user-exists-true.json)
    - Error responses with the correct error codes from ErrorResponse enum:
      - login-error-invalid-credentials.json (code: 1008)
      - user-exists-error.json (code: 1004)
      - verify-code-error-invalid.json (code: 1035)
      - verify-code-error-expired.json (code: 1027)
      - reset-password-error-invalid-code.json (code: 1021)
      - reset-password-error-expired-code.json (code: 1039)
    - Variant responses where applicable (e.g., login-success-mfa.json, login-account-locked.json)

5. Update the rest-plugin-config.yaml to include all endpoints with appropriate paths, methods, status codes, and response files. For each endpoint, create multiple resource entries to handle different scenarios:
   - Standard success path (e.g., "/login" → login-success.json)
   - Variant success paths (e.g., "/login-mfa" → login-success-mfa.json)
   - Error paths (e.g., "/login-invalid-credentials" → login-error-invalid-credentials.json)

6. Ensure all error responses use the exact error codes defined in the ErrorResponse enum in the Java implementation. All error codes should be integers in the 1000-1086 range, for example:
    - 1000: "Session-Id is missing or invalid"
    - 1008: "Invalid login credentials"
    - 1045: "User account is temporarily locked from sign in"
    - 1083: "User's account is suspended"

The mock setup should allow testing all API endpoints with different scenarios and response types.
