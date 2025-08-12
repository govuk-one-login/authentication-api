# Zero-downtime KMS key rotation for signing keys

## Context

The authentication service uses AWS KMS keys to sign JWTs for MFA reset flows. These keys need periodic rotation for security compliance, but the current system lacks a mechanism to rotate keys without service downtime.

The existing architecture has:
- KMS keys for signing JWTs sent to IPV during MFA reset
- A main signing alias (`ipv_reverification_request_signing_key_alias`) used by signing lambda handlers
- JWKS endpoint handlers that publish public keys for external verification and cache resolved keys indefinitely until container recycling
- Signing lambda handlers that resolve KMS alias names to key IDs at runtime
- External services that may cache JWKs and take time to process signed requests

The core challenge is ensuring that during key rotation, both old and new keys remain valid for signature verification while transitioning signing operations to the new key.

**Key Challenge - JWKS Caching:**
The JWKS endpoint handlers cache keys indefinitely until container recycling, making simple alias switching impossible. If we updated an alias to point to a new key, the JWKS endpoint would continue serving the cached old key, breaking verification for new signatures.

## Decision

We will implement a zero-downtime key rotation process using a main signing alias plus versioned aliases, working around JWKS caching limitations by using environment variable updates to control which keys the JWKS endpoint serves.

### Architecture

- **Main Signing Alias** (`ipv_reverification_request_signing_key_alias`): Always points to the current active key for signing operations
- **Versioned Aliases**: Individual aliases for each key version (`ipv_reverification_request_signing_key_v1_alias`, `ipv_reverification_request_signing_key_v2_alias`, etc.)

### Key Components

- **JWKS Lambda Environment Variables**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references current versioned alias for primary key
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` - references previous versioned alias for backward compatibility
- **Signing Lambda Environment Variable**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references main signing alias (not versioned)
- **Versioned Keys**: Each key has a corresponding versioned alias (`_v1_alias`, `_v2_alias`, etc.)

### Process

1. **Create New Versioned Key and Update JWKS** (Single Terraform Deployment):
   - Create new KMS key with new versioned alias (e.g., `ipv_reverification_request_signing_key_v2_alias`)
   - Update JWKS lambda environment variables:
     - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` → `_v2_alias` (new primary)
     - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` → `_v1_alias` (old for compatibility)
   - Run `terraform apply`
   - **Result**: JWKS serves both keys, signing continues with old key via main alias

2. **Switch Signing to New Key** (Single Terraform Deployment):
   - Update main signing alias to point to new key: `ipv_reverification_request_signing_key_alias` → `_v2` key
   - Run `terraform apply`
   - **Result**: New signatures use new key, JWKS still serves both keys for verification

3. **Cleanup Old Key** (Single Terraform Deployment, after external cache expiry):
   - Remove `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` environment variable
   - Delete old versioned key and `_v1_alias`
   - Run `terraform apply`
   - **Result**: JWKS serves only new key

### Deployment Timeline

**Day 1 - Complete Rotation:**
1. **Step 1**: Create new versioned key + update JWKS environment variables → `terraform apply`
2. **Step 2**: Switch main signing alias to new key → `terraform apply`
3. **Wait**: Allow time for external service cache expiry
4. **Step 3**: Remove deprecated key and environment variable → `terraform apply`

**Timeline**: Steps 1-2 can be done immediately, Step 3 after cache expiry period.

### Terraform Dependency Management

Terraform's dependency resolution ensures safe deployment ordering:
- KMS keys are created before aliases that reference them
- Aliases are created before environment variables that reference them
- Lambda deployments occur after all referenced resources exist

This prevents environment variables from referencing non-existent resources during deployment.

## Consequences

### Benefits

- **Zero downtime**: Both keys remain valid throughout rotation
- **Works with JWKS caching**: Environment variables control key serving instead of alias switching
- **Single-day rotation**: Complete rotation possible within one day
- **Clear separation**: Main alias for signing, versioned aliases for JWKS serving
- **Safe rollback**: Revert by updating environment variables to previous versions

### Trade-offs

- **Temporary dual-key state**: JWKS serves two keys during rotation period
- **Manual process**: Requires manual Terraform file updates for each rotation
- **Key cleanup required**: Old versioned keys must be removed after rotation
- **Increased complexity**: Multiple aliases instead of single alias approach

### Implementation Requirements

- Update JWKS lambda to use versioned alias environment variables
- Implement versioned key creation pattern in Terraform
- Document manual rotation process for each step
- Establish cleanup procedures for old keys and aliases
- Ensure proper Terraform dependency ordering

This approach provides secure key rotation while working within JWKS caching constraints and enabling single-day rotation cycles.