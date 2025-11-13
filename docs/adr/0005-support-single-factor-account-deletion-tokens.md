# Support Single-Factor Account Deletion Tokens in Account Management API

## Status

Accepted

## Context

The Account Management API currently accepts OIDC access tokens issued by Orchestration after users complete full authentication including MFA. However, we need to support a new use case: users who have lost access to their MFA device and cannot reset it (due to lack of verified identity) should be able to delete their accounts without contacting the Contact Centre.

To enable this, Authentication will issue an access token embedded within a transport JWT when users choose to delete their account during the authentication journey but cannot complete the MFA step. The transport JWT is passed to AMC (Account Management Components), which extracts the access token and uses it to call the Account Management API. Details of the transport JWT format and encryption are documented in the [Authentication Interface with IPV](https://govukverify.atlassian.net/wiki/spaces/Architecture/pages/4171989119/Authentication+Interface+with+IPV) Confluence page.

### Token Architecture

**Flow:**

1. Authentication creates and signs an `access_token` JWT
2. Authentication packages the access token in a transport JWT before redirecting to AMC
3. AMC extracts the `access_token` from the transport JWT
4. AMC sends the access token as bearer token in the Authorization header to Account Management API
5. Authorizer uses the `iss` and `client_id` claims to determine which JWKS endpoint to use for verification
6. Authorizer validates the JWT signature using Authentication/Orchestration's public key from JWKS

**Access token (what authorizer validates):**

- Signed by Authentication/Orchestration using their private access token signing key (separate from outer JWT signing key)
  - Signing Algorithm: ECDSA_SHA_256
  - Key Spec: ECC_NIST_P256
- Sent directly by AMC without modification (no re-signing or encryption)
- Contains standard JWT claims:
  - `sub` - Subject (RP pairwise identifier)
  - `scope` - Array of scope strings (e.g., `["openid", "email", "phone"]` or `["account-delete"]`)
  - `iss` - Issuer URL
  - `aud` - Audience (Account Management API identifier)
  - `exp` - Expiration time (Unix timestamp)
  - `iat` - Issued at time (Unix timestamp)
  - `client_id` - Client identifier
  - `jti` - JWT ID (unique identifier)
  - `sid` - Session ID
- Scope: `account-delete` (restricted access to SFAD endpoints) vs `account-management` (full access)
- Authorizer uses `iss` claim to determine JWKS endpoint for signature verification
- Validated using original issuer's public key from their JWKS endpoint

### Access Token Signing

**Access Token Signing Key:**

- Purpose: Sign access tokens for API authorization
- Algorithm: ECDSA_SHA_256 with ECC_NIST_P256
- Validation: By Account Management API authorizer using Authentication's SFAD OAuth client public signing key from JWKS endpoint

### Token Comparison

**Orchestration-issued access tokens (existing):**

- Issued after full authentication (password + MFA)
- Issuer: `"https://oidc.<env>.account.gov.uk/"`
- Client ID: <Home RP client_id>
- Scope: `["openid", "email", "phone", "account-management"]` (full access)
- Example structure:

```json
{
  "sub": "urn:fdc:gov.uk:2022:...",
  "scope": ["openid", "email", "phone", "account-management"],
  "iss": "https://oidc.<env>.account.gov.uk/",
  "aud": "<account-management-api-identifier>",
  "exp": 1758553253,
  "iat": 1758553073,
  "client_id": "<Home RP Client ID>",
  "jti": "f416dee2-6ec2-4245-83b7-e3137968f3fa",
  "sid": "IJsFfxtyIwizWdZuFu6CUB8ccEM"
}
```

**Authentication-issued single-factor access tokens (new):**

- Issued after single-factor authentication (password only)
- Issuer: `"https://signin.<env>.account.gov.uk/"`
- Client ID: <Authentication Client ID - TBD>
- Scope: `["account-delete"]` (restricted access to SFAD endpoints)
- Example structure:

```json
{
  "sub": "urn:fdc:gov.uk:2022:...",
  "scope": ["account-delete"],
  "iss": "https://signin.<env>.account.gov.uk/",
  "aud": "<account-management-api-identifier>",
  "exp": 1758553253,
  "iat": 1758553073,
  "client_id": "<Authentication Client ID - TBD>",
  "jti": "f416dee2-6ec2-4245-83b7-e3137968f3fa",
  "sid": "IJsFfxtyIwizWdZuFu6CUB8ccEM"
}
```

**Key differences:**

- **Issuer**: Different `iss` values identify the token source
- **Scope**: `account-management` (full access) vs `account-delete` (restricted)
- **Client ID**: Will be different values

**Commonalities:**

- Same JWT structure with standard claims (`sub`, `scope`, `iss`, `aud`, `exp`, `iat`, `client_id`, `jti`, `sid`)
- Signed using ECDSA_SHA_256 with ECC_NIST_P256
- Sent as-is by AMC (no modification, re-signing, or encryption)
- Validated using original issuer's JWKS endpoint based on `iss` claim and `client_id` claims
- Include `aud` claim for the Account Management API

### Options Considered

#### Option 1: New API Gateway with New Authorizer (DISCOUNTED)

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

#### Option 4: Different Routes on Same Gateway (DISCOUNTED)

Deploy lambdas at different URI paths (e.g., `/v2/*`) with a new authorizer on the same API Gateway.

**Pros:**

- Separation of concerns for authorizers
- Reuses existing infrastructure

**Cons:**

- Creates parallel URI structure to maintain
- More complex routing logic
- Unnecessary given token similarity

## Decision

We will implement **Option 2: Modify the existing authorizer** to support both Orchestration-issued and Authentication-issued tokens.

### Rationale

1. **Token Similarity**: Both tokens are JWTs with similar structure (signed, contain `sub` and `iss`, have expiration). The primary differences are scope values and optional claims, which can be handled with conditional logic.

2. **Scope-Based Access Control**: The different issuer and scope values (`account-management` vs `account-delete`) provide a natural mechanism to restrict single-factor tokens to SFAD-specific endpoints (OTP operations, password validation, account deletion). This can be implemented in the authorizer's policy generation.

3. **Cost Efficiency**: Avoids doubling API Gateway infrastructure costs while achieving the same security goals.

4. **Operational Simplicity**: One authorizer to monitor, debug, and maintain rather than two parallel systems.

5. **Proportional Complexity**: The added complexity in the authorizer is proportional to the actual difference between token types (minimal), whereas Options 1 and 4 add infrastructure complexity disproportionate to the problem.

### Token Differentiation Strategy

The authorizer must distinguish between Orchestration-provisioned and Authentication-provisioned access tokens to apply appropriate validation and access control. The key challenge is determining which JWKS endpoint to use for signature verification without creating a circular dependency.

**Secure Token Validation Approach:**

The authorizer will use a two-step process to safely determine the correct JWKS endpoint:

1. **Extract and validate issuer domain**: Read the `iss` claim from the unverified token and perform exact string match against an allowlist of permitted issuer domains
2. **Map client ID to JWKS URL**: Use the `client_id` claim to look up the specific JWKS endpoint from a configured mapping

**Implementation steps:**

```
1. Parse JWT header and payload (without signature verification)
2. Extract iss claim and validate against allowlisted domains:
   - "https://signin.<env>.account.gov.uk" (Authentication)
   - "https://oidc.<env>.account.gov.uk" (Orchestration)
3. Extract client_id claim and map to JWKS URL:
   - Authentication Client ID (TBD) -> "https://signin.<env>.account.gov.uk/.well-known/amc-jwks.json"
   - Home RP Client ID -> "https://oidc.<env>.account.gov.uk/.well-known/jwks.json"
4. Fetch public key from mapped JWKS endpoint
5. Verify JWT signature using fetched public key
6. Validate issuer and client_id claims match expected values
7. Apply scope-based authorization rules
```

**Security considerations:**

- **Domain allowlisting**: Only trusted issuer domains are accepted, preventing malicious JWKS endpoint attacks
- **Static JWKS mapping**: Client ID to JWKS URL mapping is configured statically, not derived from token content
- **Post-verification validation**: Issuer and client ID claims are re-validated after signature verification
- **Multiple JWKS support**: Allows Auth to host multiple JWKS endpoints on the same domain for different purposes

**JWKS endpoint strategy:**

Auth will host separate JWKS endpoints for different OAuth clients:

- `https://signin.account.gov.uk/.well-known/amc-jwks.json` - Account Management Components tokens
- `https://signin.account.gov.uk/.well-known/mfa-reset-jwks.json` - MFA reset tokens (existing)
- `https://signin.account.gov.uk/.well-known/reverification-jwks.json` - IPV reverification tokens (existing)

**Combined validation approach:**

After successful signature verification, the authorizer will validate both issuer and scope claims:

- Orchestration tokens: `iss: "https://oidc.account.gov.uk"` AND `client_id: "<Home RP Client ID>"` AND `scope: ["account-management"]`
- Auth tokens: `iss: "https://signin.account.gov.uk"` AND `client_id: "<Authentication Client ID - TBD>"` AND `scope: ["account-delete"]`

**Benefits of this approach:**

- **Security**: No circular dependency between token content and signature verification
- **Flexibility**: Supports multiple JWKS endpoints per domain
- **Defense in depth**: Multiple validation layers (domain allowlist, static mapping, post-verification checks)
- **Standards alignment**: Uses standard JWT claims for token identification
- **Clear provenance**: Issuer and client ID claims explicitly identify token source for audit trails
- **Semantic authorization**: Scope claim provides clear authorization boundary
- **Future flexibility**: Allows Auth to issue different token types while maintaining secure validation
- **Standards alignment**: Uses standard JWT claims per OAuth 2.0 and OpenID Connect specifications

**Authorization logic:**

```
IF iss == "https://oidc.account.gov.uk" AND client_id == "{Home RP Client ID}" AND scope contains "account-management" THEN
  → Orchestration token: Allow all endpoints
ELSE IF iss == "https://signin.account.gov.uk" AND client_id == "{Authentication Client ID}" AND scope contains "account-delete" THEN
  → Auth token: Allow only endpoints permitted by account-delete scope
ELSE
  → Invalid token combination: Deny access
```

This prevents scenarios where:

- An Auth-issued token with `account-management` scope is accepted (shouldn't happen)
- Tokens with mismatched issuer/scope combinations bypass validation

### Implementation Approach

Once the differentiation strategy is chosen, the authorizer will:

1. **Parse JWT** - Extract claims from the bearer token JWT
2. **Validate common requirements** - Expiration, signature, subject presence
3. **Detect token type** - Check both `iss` and `scope` claims
4. **Apply type-specific validation**:
   - Orchestration tokens: Validate `iss` matches Orchestration issuer AND `scope` contains `account-management` AND `client_id` present
   - Auth tokens: Validate `iss` matches Auth issuer AND `scope` contains `account-delete` AND `client_id` present
   - Reject tokens with mismatched issuer/scope combinations
5. **Generate appropriate policy**:
   - Orchestration tokens: Allow all endpoints (`getAllowAllPolicy`)
   - Auth tokens: Restrict to endpoints permitted by the scoped policy
6. **Pass context** - Include `clientId` and token type/scope for audit logging

### Scope-Based Access Control

If scope-based differentiation is chosen, the authorizer will implement endpoint restrictions to prevent unauthorised usage.
**`account-management` scope (Orchestration tokens):**

- All actions permitted
  **`account-delete` scope (Auth tokens):**
- Only endpoints necessary to perform account deletion are permitted
- This ensures single-factor authenticated users can only delete their accounts, not modify account details.

### Risks and Mitigations

**Risk**: Bug in authorizer affects both Orchestration and single-factor flows
**Mitigation**: Comprehensive unit and integration tests covering both token types, feature flag for gradual rollout

**Risk**: Incorrect policy generation allows single-factor tokens to access restricted endpoints
**Mitigation**: Explicit scope-to-endpoint mapping, integration tests verifying access restrictions

**Risk**: Performance impact from additional validation logic
**Mitigation**: Authorizer results are cached by API Gateway, minimal performance impact expected

## JWKS Configuration

The authorizer will use a secure two-step approach to determine the correct JWKS endpoint:

**Static JWKS Mapping Configuration:**

```
Client ID -> JWKS URL Mapping:
- "<Home RP Client ID>" -> "https://oidc.account.gov.uk/.well-known/jwks.json"
- "<Authentication Client ID - TBD>" -> "https://signin.account.gov.uk/.well-known/amc-jwks.json"

Allowed Issuer Domains:
- "https://oidc.account.gov.uk" (Orchestration)
- "https://signin.account.gov.uk" (Authentication)
```

**Implementation approach:**

1. Parse JWT and extract `iss` and `client_id` claims (before signature verification)
2. Validate issuer domain is in allowlist:
   - `"https://oidc.account.gov.uk"` (Orchestration)
   - `"https://signin.account.gov.uk"` (Authentication)
3. Map client ID to JWKS endpoint using static configuration:
   - `"{Home RP Client ID}"` -> `https://oidc.account.gov.uk/.well-known/jwks.json`
   - `"{Authentication Client ID - TBD}"` -> `https://signin.account.gov.uk/.well-known/amc-jwks.json`
4. Fetch public signing key from mapped JWKS endpoint (with caching)
5. Validate JWT signature using fetched public key
6. Re-validate issuer and client_id claims match expected values post-verification
7. Validate scope combination matches expected pattern for the client

## Notes

- The client assertion JWT (containing OAuth flow claims) is used for secure transport from Auth to AMC.
- AMC decrypts the client assertion JWT (using AMC's RSA_2048 private key), extracts the inner access token, then sends it as-is to Account Management API.
- The authorizer validates the JWT signature directly (using Auth/Orchestration's ECC_NIST_P256 public key from the appropriate JWKS endpoint based on the token's issuer).
- Both signing and encryption use industry-standard algorithms: ECDSA_SHA_256 for signatures, RSAES_OAEP_SHA_256 for encryption.
- Both token types will contain `iss` and `client_id`, maintaining consistency with existing validation logic and audit requirements.
- The `/delete-account` endpoint (RemoveAccountHandler) validates that the subject in the token matches the account being deleted.
- API Gateway caches authorizer results for up to 1 hour by default. We would like the results to be cached for the same amount of time as the token lifetime. If this is different, the cacheing period will need specifying.
- The authorizer will use separate JWKS endpoints for Auth and Orchestration, determined by static client ID mapping after issuer domain validation.
- Auth will host multiple JWKS endpoints to support different OAuth clients and use cases (AMC, MFA reset, IPV reverification).
- The static client ID to JWKS URL mapping prevents attacks where malicious tokens could direct the authorizer to attacker-controlled JWKS endpoints.
