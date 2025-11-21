# Support Single-Factor Account Deletion Tokens in Account Management API

## Status

Proposed

## Context

The Account Management API currently accepts OIDC access tokens issued by Orchestration after users complete full authentication including MFA. However, we need to support a new use case: users who have lost access to their MFA device and cannot reset it (due to lack of verified identity) should still be able to delete their accounts.

To enable this, Auth will issue a signed and encrypted JWT (outer token) containing an embedded access token when users choose to delete their account during the authentication journey but cannot complete the MFA step. This outer token will be passed to Home (Account Management Components), which will extract the inner access token and use it to call the Account Management API.

### Token Architecture

**Flow:**

1. Auth issues a **signed + encrypted JWT** (outer) before redirecting to Home
2. Outer JWT contains claims including an embedded `access_token` (inner signed JWT)
3. Home decrypts outer JWT and extracts the inner `access_token`
4. Home **resigns** the access token using Home's private signing key
5. Home **encrypts** the resigned access token using Account Management API's public encryption key
6. Home sends the encrypted access token in the Authorization header to Account Management API
7. Authorizer **decrypts** the token using Account Management API's private key
8. Authorizer validates the decrypted JWT (signature via Home's public key in JWKS, expiration, issuer, scope)

**Outer JWT (transport container - Auth to Home):**

- Signed by Auth using Auth private signing key
  - Signing Algorithm: ECDSA_SHA_256
  - Key Spec: ECC_NIST_P256
- Encrypted by Auth using Home public encryption key
  - Encryption Algorithm: RSAES_OAEP_SHA_256
  - Key Spec: RSA_2048
- Contains: `iss`, `client_id`, `aud`, `response_type`, `redirect_uri`, `scope`, `state`, `jti`, `iat`, `exp`, `access_token` (embedded), `refresh_token`, `sub`, `email`, `govuk_signin_journey_id`
- Purpose: Secure transport to Home
- Not validated by Account Management API authorizer

**Inner access token (what authorizer validates):**

- Originally signed by Auth/Orchestration using their private signing key
- **Resigned by Home** using Home's private signing key before transmission
  - Signing Algorithm: ECDSA_SHA_256
  - Key Spec: ECC_NIST_P256
- Encrypted by Home using Account Management API public encryption key before transmission
  - Encryption Algorithm: RSAES_OAEP_SHA_256
  - Key Spec: RSA_2048
- JWT has same format as current Orchestration tokens
- Contains: `iss`, `client_id`, `scope`, `sub`, and other standard access token claims
- Scope: `account-delete` (restricted) vs `account-management` (full access)
- Authorizer must decrypt (using Account Management API private key) then validate signature via Home's public key in JWKS

### Token Comparison

**Orchestration-issued access tokens (current):**

- Issued after full authentication (password + MFA)
- Issuer: `"orchestrationAuth"`
- Client ID: `"orchestrationAuth"`
- Scope: `account-management` (full access)
- Contains: `iss`, `client_id`, `scope`, `sub`, standard OIDC claims
- Resigned by Home using Home's private signing key
- Encrypted by Home before transmission to Account Management API

**Auth-issued single-factor access tokens (new):**

- Issued after single-factor authentication (password only)
- Issuer: `"auth"`
- Client ID: `"auth"`
- Scope: `account-delete` (restricted access)
- Contains: `iss`, `client_id`, `scope`, `sub`, and standard access token claims
- Resigned by Home using Home's private signing key
- Encrypted by Home before transmission to Account Management API

Both access token types:

- Originally signed by Auth/Orchestration using ECDSA_SHA_256 with ECC_NIST_P256 keys
- **Resigned by Home** using Home's private signing key (ECDSA_SHA_256 with ECC_NIST_P256)
- Encrypted using RSAES_OAEP_SHA_256 with RSA_2048 keys before transmission
- Contain `iss`, `client_id`, `sub`, and `scope` claims
- Require decryption then signature validation via Home's public key in JWKS
- Have expiration times

### Options Considered

#### Option 1: New API Gateway with New Authorizer

Create a parallel API Gateway stack with a separate authorizer for single-factor tokens, deploying the same Lambda handlers behind both gateways.

**Pros:**

- Complete separation of concerns
- No risk of breaking existing Orchestration flow
- Can selectively deploy endpoints to different gateways

**Cons:**

- Doubles infrastructure costs (two API Gateways)
- Operational complexity managing two identical stacks
- Unnecessary duplication given token similarity

#### Option 2: Modify Existing Authorizer (SELECTED)

Modify `AuthoriseAccessTokenHandler` to detect and validate both token types within the same authorizer.

**Pros:**

- Minimal infrastructure changes
- Tokens are similar enough (both JWTs with subject) to share validation logic
- Downstream lambdas already handle missing `client_id` gracefully
- Can implement scope-based access control in one place
- Lower operational overhead

**Cons:**

- Increased authorizer complexity
- Single point of failure for both flows
- Requires careful testing to avoid breaking existing functionality

#### Option 3: Orchestration Supplies Token (DISCOUNTED)

Have Orchestration issue tokens for unauthenticated users.

**Pros:**

- No authorizer changes needed

**Cons:**

- Security risk: tokens would have full `account-management` scope
- Significant Orchestration work to support unauthenticated token issuance
- Doesn't align with single-factor authentication model

#### Option 4: Different Routes on Same Gateway

Deploy lambdas at different URI paths (e.g., `/v2/*`) with a new authorizer on the same API Gateway.

**Pros:**

- Separation of concerns for authorizers
- Reuses existing infrastructure

**Cons:**

- Creates parallel URI structure to maintain
- More complex routing logic
- Unnecessary given token similarity

## Decision

We will implement **Option 2: Modify the existing authorizer** to support both Orchestration-issued and Auth-issued tokens.

### Rationale

1. **Token Similarity**: Both tokens are JWTs with similar structure (signed, contain `sub`, have expiration). The primary differences are scope values and optional claims, which can be handled with conditional logic.

2. **Consistent Token Structure**: Both token types contain `client_id`, `sub`, and `scope` claims, maintaining consistency with existing token validation logic.

3. **Scope-Based Access Control**: The different scope values (`account-management` vs `account-delete`) provide a natural mechanism to restrict single-factor tokens to specific endpoints. This can be implemented in the authorizer's policy generation.

4. **Cost Efficiency**: Avoids doubling API Gateway infrastructure costs while achieving the same security goals.

5. **Operational Simplicity**: One authorizer to monitor, debug, and maintain rather than two parallel systems.

6. **Proportional Complexity**: The added complexity in the authorizer is proportional to the actual difference between token types (minimal), whereas Options 1 and 4 add infrastructure complexity disproportionate to the problem.

### Token Differentiation Strategy

The authorizer must distinguish between Orchestration-provisioned and Auth-provisioned access tokens to apply appropriate validation and access control. Several approaches are possible:

**Option A: Scope-based differentiation**

- Orchestration tokens: `scope: ["account-management"]`
- Auth tokens: `scope: ["account-delete"]`
- Pros: Clear semantic meaning, natural access control boundary
- Cons: Requires new scope value definition

**Option B: Issuer-based differentiation**

- Orchestration tokens: `iss: "orchestrationAuth", client_id: "orchestrationAuth"`
- Auth tokens: `iss: "auth"`, `client_id: "auth"`
- Pros: Standard JWT claim, clear token provenance
- Cons: Requires different JWKS endpoints or issuer validation logic

**Option C: Custom claim**

- Auth tokens include: `credential_trust_level: "LOW_LEVEL"` or `auth_level: "single-factor"`
- Orchestration tokens: No such claim or `credential_trust_level: "MEDIUM_LEVEL"`
- Pros: Explicit authentication level indication
- Cons: Non-standard claim, requires coordination across services

**Recommendation: Combined Approach (Scope-based AND Issuer-based)**

Using both scope and issuer claims together provides the strongest security model:

**Combined validation:**

- Orchestration tokens: `iss: "orchestrationAuth"` AND `scope: ["account-management"]`
- Auth tokens: `iss: "auth"` AND `scope: ["account-delete"]`

**Benefits of combined approach:**

- **Defense in depth**: Two independent validation mechanisms reduce risk of token confusion attacks
- **Clear provenance**: Issuer claim explicitly identifies token source for audit trails
- **Semantic authorization**: Scope claim provides clear authorization boundary
- **Future flexibility**: Allows Auth to issue different token types (e.g., `account-delete`, `account-view`) while maintaining issuer identity
- **Standards alignment**: Uses standard JWT claims (`iss`, `scope`) per OAuth 2.0 and OpenID Connect specifications
- **Explicit validation**: Authorizer can validate both claims match expected combinations, rejecting malformed tokens

**Validation logic:**

```
IF iss == "orchestrationAuth" AND scope contains "account-management" THEN
  → Orchestration token: Allow all endpoints
ELSE IF iss == "auth" AND scope contains "account-delete" THEN
  → Auth token: Allow only /delete-account
ELSE
  → Invalid token combination: Deny
```

This prevents scenarios where:

- An Auth-issued token with `account-management` scope is accepted (shouldn't happen)
- An Orchestration-issued token with `account-delete` scope is accepted (shouldn't happen)
- Tokens with mismatched issuer/scope combinations bypass validation

### Implementation Approach

Once the differentiation strategy is chosen, the authorizer will:

1. **Decrypt token** - Decrypt the bearer token using Account Management API's private key to obtain the signed JWT
2. **Parse JWT** - Extract claims from the decrypted JWT
3. **Validate common requirements** - Expiration, signature, subject presence
4. **Detect token type** - Check both `iss` and `scope` claims
5. **Apply type-specific validation**:
   - Orchestration tokens: Validate `iss` matches Orchestration issuer AND `scope` contains `account-management` AND `client_id` present
   - Auth tokens: Validate `iss` matches Auth issuer AND `scope` contains `account-delete` AND `client_id` present
   - Reject tokens with mismatched issuer/scope combinations
6. **Generate appropriate policy**:
   - Orchestration tokens: Allow all endpoints (`getAllowAllPolicy`)
   - Auth tokens: Restrict to `/delete-account` endpoint only (scoped policy)
7. **Pass context** - Include `clientId` and token type/scope for audit logging

### Scope-Based Access Control

If scope-based differentiation is chosen, the authorizer will implement endpoint restrictions:

**`account-management` scope (Orchestration tokens):**

- `/send-otp-notification` - ✓ Allowed
- `/verify-otp-notification` - ✓ Allowed
- `/update-email` - ✓ Allowed
- `/update-password` - ✓ Allowed
- `/update-phone-number` - ✓ Allowed
- `/delete-account` - ✓ Allowed
- All other endpoints - ✓ Allowed

**`account-delete` scope (Auth tokens):**

- `/delete-account` - ✓ Allowed
- All other endpoints - ✗ Denied (403 Forbidden)

This ensures single-factor authenticated users can only delete their accounts, not modify account details.

## Consequences

### Positive

- Single-factor users can delete accounts without MFA access
- Minimal infrastructure changes required
- Reuses existing validation infrastructure (JWKS, signature verification)
- Clear scope-based access control model
- Downstream lambdas require no changes

### Negative

- Authorizer becomes a single point of failure for both authentication flows
- Increased code complexity in authorizer requires thorough testing
- Need to ensure scope-based policy restrictions are correctly implemented
- Monitoring and alerting must cover both token types

### Risks and Mitigations

**Risk**: Bug in authorizer affects both Orchestration and single-factor flows
**Mitigation**: Comprehensive unit and integration tests covering both token types, feature flag for gradual rollout

**Risk**: Incorrect policy generation allows single-factor tokens to access restricted endpoints
**Mitigation**: Explicit scope-to-endpoint mapping, integration tests verifying access restrictions

**Risk**: Performance impact from additional validation logic
**Mitigation**: Authorizer results are cached by API Gateway, minimal performance impact expected

## JWKS Configuration

The authorizer will use separate JWKS endpoints for Home and Orchestration, routing based on the issuer claim:

**Configuration:**

- Home JWKS: `https://api.manage.account.gov.uk/.well-known/jwks.json` (production) or `https://api.manage.{env}.account.gov.uk/.well-known/jwks.json` (non-production)
- Orchestration JWKS: `https://oidc.account.gov.uk/.well-known/jwks.json` (production) or `https://oidc.{env}.account.gov.uk/.well-known/jwks.json` (non-production)

**Implementation approach:**

1. Decrypt bearer token using Account Management API's private encryption key
2. Parse JWT and extract `iss` claim
3. Validate issuer is in allowed list:
   - `"orchestrationAuth"` (Orchestration)
   - `"auth"` (Auth)
4. Derive JWKS endpoint from issuer or scope:
   - Orchestration: use orchestration JWKS - `https://oidc.account.gov.uk/.well-known/jwks.json`
   - Auth: use Account Management Components (Home) JWKS - `https://api.manage.account.gov.uk/.well-known/jwks.json`
5. Fetch public signing key from appropriate JWKS endpoint (with caching)
6. Validate JWT signature using fetched public key
7. Validate issuer/scope combination matches expected pattern

## Open Questions

1. **Key rotation**: How will key rotation be handled for both signing and encryption keys? What is the rotation schedule?

2. **Token lifetime**: Should Auth-issued access tokens have a shorter expiration time than Orchestration tokens given the reduced authentication level?

3. **Refresh token support**: Will the refresh token in the outer JWT be used to obtain new access tokens? If so, what endpoint handles refresh?

4. **JWKS caching**: What caching strategy should be used for JWKS endpoints? Should Home and Orchestration JWKS be cached separately with different TTLs?

## Notes

- The outer JWT (containing OAuth flow claims) is only used for secure transport from Auth to Home and is not sent to Account Management API.
- Home decrypts the outer JWT (using Home's RSA_2048 private key), extracts the inner access token, then re-encrypts it (using Account Management API's RSA_2048 public key) before sending to Account Management API.
- The authorizer must decrypt the bearer token first (using Account Management API's RSA_2048 private key via KMS), then validate the JWT signature (using Home/Orchestration's ECC_NIST_P256 public key from the appropriate JWKS endpoint based on the token's issuer).
- Both signing and encryption use industry-standard algorithms: ECDSA_SHA_256 for signatures, RSAES_OAEP_SHA_256 for encryption.
- Both token types will contain `iss` and `client_id`, maintaining consistency with existing validation logic and audit requirements.
- Auth-issued access tokens will contain `iss: "auth"` and `client_id: "auth"`.
- Orchestration-issued access tokens contain `iss: "orchestrationAuth"` and `client_id: "orchestrationAuth"`.
- Both `"auth"` and `"orchestrationAuth"` serve dual purposes: they identify the service as an OIDC client when calling other services, and they appear as the `client_id` claim in the access tokens they issue.
- The `/delete-account` endpoint (RemoveAccountHandler) validates that the subject in the token matches the account being deleted.
- API Gateway caches authorizer results for up to 1 hour by default, which may need adjustment for single-factor tokens.
- The decryption step adds latency to authorization; performance testing should validate acceptable response times.
- KMS key policies must allow the authorizer Lambda to use the Account Management API's private decryption key.
- The authorizer will use separate JWKS endpoints for Auth and Orchestration, routing based on the `iss` claim in the decrypted JWT.
- JWKS responses should be cached to minimize latency; cache invalidation strategy must account for key rotation events.
