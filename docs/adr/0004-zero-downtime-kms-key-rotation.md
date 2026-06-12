# Zero-downtime KMS key rotation for signing keys

## Context

The authentication service uses AWS KMS keys to sign JSON Web Tokens (JWTs)
for MFA reset journeys sent to the Identity Proofing and Verification (IPV)
service. External services like IPV verify these signatures by retrieving
public keys from JWKS (JSON Web Key Set) endpoints that the authentication
service exposes.

Security compliance requires periodic key rotation, but the system must
maintain zero downtime during this process. The primary challenge is ensuring
continuous signature verification during key rotation—both old and new keys
must remain available for verification while signing operations transition to
the new key.

JWKS endpoints implement aggressive caching for performance, serving the same
cached public key until container restart. This creates a coordination problem
during rotation: signing operations can immediately switch to a new key, but
JWKS endpoints continue serving the old cached public key, causing signature
verification failures.

## Existing Architecture

Before implementing rotation support, the system used a simple key
architecture with direct alias references.

### Key Infrastructure

The system uses AWS KMS aliases—human-readable names that point to KMS
keys—instead of cryptographic key IDs for easier identification and
management.

Two signing keys support MFA reset operations:

- **MFA Reset Storage Token Key** (`mfa_reset_token_signing_key_ecc`)
  - Type: ECC P-256
  - Purpose: Signs the storage token claim within MFA reset JARs
  - JWKS endpoint: `/.well-known/mfa-reset-storage-token-jwk.json`

- **IPV Reverification Request Key** (`ipv_reverification_request_signing_key`)
  - Type: ECC P-256
  - Purpose: Signs the complete JAR sent to IPV for MFA reset
  - Alias: `ipv_reverification_request_signing_key_alias`
  - JWKS endpoint: `/.well-known/reverification-jwk.json`
  - Lambda configuration: `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS = ipv_reverification_request_signing_key_alias`

### JWKS Endpoint Behavior

JWKS (JSON Web Key Set) endpoints serve public keys to external services
for signature verification. These endpoints implement aggressive caching:

1. On first request, retrieve public key from KMS using the configured alias
2. Cache the key in memory indefinitely
3. Serve cached key for all subsequent requests until container restart
4. No additional KMS calls after initial retrieval

This caching strategy optimizes performance but creates the core rotation
challenge.

## Decision

We implemented zero-downtime key rotation using versioned KMS keys with
dual-key JWKS serving during transition periods.

### The Core Problem

JWKS endpoints cache keys indefinitely until container recycling. A naive
rotation approach—simply updating the main signing alias to point to a new
KMS key—would create a verification failure:

1. Signing lambdas immediately use the new key for signatures
2. JWKS endpoint continues serving the cached old public key
3. IPV attempts to verify new signatures using the old public key
4. Verification fails, breaking the service

### Solution Architecture

#### Steady-State Configuration

During normal operations (no rotation in progress), the system maintains a
simple configuration:

```
┌─────────────────┐    ┌──────────────────────────────────────┐
│   Signing       │    │              KMS                     │
│   Lambdas       │    │                                      │
│                 │    │  ┌─────────────────────────────────┐ │
│  Uses alias: ───┼────┼─►│ ipv_reverification_request_     │ │
│  ...alias       │    │  │ signing_key_alias               │ │
│                 │    │  │           │                     │ │
└─────────────────┘    │  │           ▼                     │ │
                       │  │  ┌─────────────────────────────┐│ │
┌─────────────────┐    │  │  │ ipv_reverification_request_ ││ │
│   JWKS          │    │  │  │ signing_key (v2)            ││ │
│   Lambda        │    │  │  │                             ││ │
│                 │    │  │  └─────────────────────────────┘│ │
│  Env var: ──────┼────┼─►└─────────────────────────────────┘ │
│  ...ALIAS       │    │                                      │
│                 │    └──────────────────────────────────────┘
│  Serves: ───────┼───► Single key in JWKS response
│  Public key     │
└─────────────────┘
```

**Key Infrastructure:**
- Primary key: `ipv_reverification_request_signing_key` (ECC P-256)
- Main signing alias: `ipv_reverification_request_signing_key_alias`

**Lambda Configuration:**
- Signing lambdas: Use `ipv_reverification_request_signing_key_alias` for all signing operations
- JWKS lambda: Configured with `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS = ipv_reverification_request_signing_key_alias`

**JWKS Endpoint Operation:**
1. Read `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` environment variable
2. Resolve alias to `ipv_reverification_request_signing_key_alias`
3. Retrieve public key from KMS using this alias
4. Cache key in memory until container restart
5. Serve the single cached key in all JWKS responses

#### Key Rotation Strategy

**Why Create New Keys Instead of Using AWS Automatic Rotation**

AWS KMS automatic key rotation only rotates the underlying key material
while preserving the same key ID and aliases. This approach would not solve
our caching problem—the JWKS endpoint would continue serving the same cached
public key even after automatic rotation, since the key ID remains unchanged.

By creating entirely new keys with new key IDs, we gain precise control over
which key version the JWKS endpoint serves through environment variable
configuration.

**Alias Architecture**

The rotation solution employs a three-tier alias strategy:

1. **Versioned aliases** (e.g., `ipv_reverification_request_signing_key_v1_alias`)
   - Always point to specific key versions
   - Never change once created
   - Enable precise key identification

2. **Main signing alias** (`ipv_reverification_request_signing_key_alias`)
   - Points to the current active key for signing operations
   - Updated during rotation to switch signing operations
   - Used by signing lambdas

3. **Environment variable control**
   - JWKS lambda uses environment variables to determine which versioned aliases to serve
   - Enables independent control of signing vs. serving operations
   - Allows dual-key serving during rotation

**Dual-Key Serving Mechanism**

The `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` environment
variable controls dual-key serving:

```
During Rotation (Dual-Key Mode):

┌─────────────────┐    ┌──────────────────────────────────────┐
│   JWKS          │    │              KMS                     │
│   Lambda        │    │                                      │
│                 │    │  ┌─────────────────────────────────┐ │
│  Primary env: ──┼────┼─►│ ...signing_key_v2_alias         │ │
│  ...ALIAS       │    │  │           │                     │ │
│                 │    │  │           ▼                     │ │
│  Deprecated: ───┼────┼─►│ ...signing_key_v1_alias         │ │
│  ...DEPRECATED_ │    │  │           │                     │ │
│  ALIAS          │    │  │           ▼                     │ │
│                 │    │  │  ┌─────────────────────────────┐│ │
│  Serves: ───────┼───►│  │  │ v2 key + v1 key             ││ │
│  Both keys      │    │  │  │ in same JWKS response       ││ │
└─────────────────┘    │  │  └─────────────────────────────┘│ │
                       │  └─────────────────────────────────┘ │
                       └──────────────────────────────────────┘
```

- **When unset**: JWKS serves only the primary key
- **When set**: JWKS serves both primary and old keys in the same response
- **Transition control**: Enables switching between single-key and dual-key modes without code changes

This mechanism prevents verification failures by ensuring both old and new
keys remain available for signature verification during the rotation window.

#### Rotation Process

```
Rotation Timeline:

Phase 1: Infrastructure    Phase 2: Versioning       Phase 3: Dual Serving
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│ Create v2 key       │──►│ Create v1/v2 aliases│──►│ JWKS serves both    │
│ Create temp alias   │   │ Remove temp alias   │   │ v1 + v2 keys        │
│ Update IAM policies │   │                     │   │                     │
└─────────────────────┘   └─────────────────────┘   └─────────────────────┘
                                                                │
                                                                ▼
Phase 5: Cleanup           Phase 4: Switch Signing  ┌─────────────────────┐
┌─────────────────────┐   ┌─────────────────────┐   │ Signing: v1 key     │
│ Remove v1 from JWKS │◄──│ Main alias → v2 key │   │ JWKS: v1 + v2 keys  │
│ JWKS serves v2 only │   │ Signing uses v2     │   │                     │
│ Delete v1 resources │   │                     │   └─────────────────────┘
└─────────────────────┘   └─────────────────────┘
```

**Phase 1: Create New Key Infrastructure**
- Create new versioned key: `ipv_reverification_request_signing_key_v2`
- Create temporary secondary alias: `ipv_reverification_request_signing_key_secondary_alias`
- Update IAM policies to grant access to the new key

**Phase 2: Establish Versioned Aliases**
- Create versioned alias for new key: `ipv_reverification_request_signing_key_v2_alias`
- Create versioned alias for existing key: `ipv_reverification_request_signing_key_v1_alias`
- Remove temporary secondary alias (no longer needed)

**Phase 3: Enable Dual-Key Serving**
- Configure old key serving: `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS = ipv_reverification_request_signing_key_v1_alias`
- Configure new key serving: `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS = ipv_reverification_request_signing_key_v2_alias`
- Deploy changes: JWKS now serves both v1 (old) and v2 (new) keys simultaneously

**Phase 4: Switch Signing Operations**
- Update main signing alias: `ipv_reverification_request_signing_key_alias` → points to v2 key
- Deploy changes: New signatures use v2 key while JWKS continues serving both keys

**Phase 5: Complete Rotation**
- Remove old key from serving: Unset `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS`
- Deploy changes: JWKS serves only v2 key
- Clean up: Delete v1 key and associated alias resources

## Consequences

### Benefits Achieved

- **Zero service interruption**: Successfully completed v1 to v2 key rotation without downtime
- **Continuous verification**: JWKS served both keys during transition, ensuring all signatures remained verifiable
- **Clear key identification**: Explicit versioning (v1/v2) eliminated confusion during rotation
- **Safe deployment**: Staged rollout across environments with rollback capability at each phase
- **External service compatibility**: IPV maintained ability to verify signatures throughout the rotation period

### Trade-offs Accepted

- **Manual orchestration**: Required careful sequencing of Terraform deployments across environments
- **Increased complexity**: Temporarily served multiple keys, adding operational complexity
- **External coordination**: Required notification to IPV team for fallback key configuration updates
- **Resource cleanup overhead**: Manual removal of deprecated key resources after rotation completion