# Zero-downtime KMS key rotation for signing keys

## Context

The authentication service uses AWS KMS keys to sign JWTs and JARs (JWT Authorization Requests) for MFA reset flows. These keys need periodic rotation for security compliance, but the current system lacks a mechanism to rotate keys without service downtime.

The existing architecture has:
- KMS keys for signing JWTs sent to IPV during MFA reset
- JWKS endpoints that publish public keys for external verification
- Lambda handlers that cache KMS keys indefinitely until container recycling
- External services that may take a long time to process the signed requests sent to them

The challenge is ensuring that during key rotation, both old and new keys remain valid for signature verification while transitioning signing operations to the new key.

**Previous Solution Issues:**
The original preferred solution using KMS aliases proved unworkable due to JWKS endpoint caching behavior. The JWKS endpoints cache the keys they serve, making it impossible to seamlessly transition between keys using the original alias-switching approach.

## Decision

We will implement a three-alias zero-downtime key rotation process that works around JWKS caching limitations by using versioned keys and environment variable updates.

### Architecture

- **Current Alias** (`ipv_reverification_request_signing_key_current_alias`): Points to the key currently served by JWKS endpoints
- **Secondary Alias** (`ipv_reverification_request_signing_key_secondary_alias`): Points to the secondary key served by JWKS endpoints
- **Signing Alias** (`ipv_reverification_request_signing_key_alias`): Points to the key used by signing lambda handlers

### Key Components

- **JWKS Lambda Environment Variables**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references current alias
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_SECONDARY_ALIAS` - references secondary alias
- **Signing Lambda Environment Variable**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references signing alias
- **Versioned Keys**: New keys created with version suffixes (`_v1`, `_v2`, etc.)

### Process

1. **Create New Versioned Key and Update JWKS** (Single Terraform Deployment):
   - Manually add new KMS key with version suffix to Terraform files (e.g., `ipv_reverification_request_signing_key_v2`)
   - Manually update JWKS lambda environment variables to reference both old and new keys
   - Run single `terraform apply`
   - **Terraform Dependency Guarantee**: Environment variables are updated only after KMS key creation succeeds due to Terraform's dependency graph
   - JWKS now serves both keys for verification
   - Signing continues with old key

2. **Switch Signing to New Key** (Single Terraform Deployment):
   - Manually update signing alias target to point to new versioned key in Terraform files
   - Run `terraform apply`
   - All new signatures use the new key
   - JWKS continues serving both keys

3. **Cleanup Old Key** (Single Terraform Deployment, after external cache expiry):
   - Manually remove old key references from JWKS lambda environment variables in Terraform files
   - Manually remove old versioned key and alias from Terraform files
   - Run `terraform apply`
   - JWKS serves only new key

### Deployment Timeline

**Day 1 - Complete Rotation:**
1. **Step 1**: Manual Terraform file updates + `terraform apply` (create `_v2` key, update JWKS to serve both keys)
2. **Step 2**: Manual Terraform file updates + `terraform apply` (switch signing alias to `_v2` key)
3. Wait for external service cache expiry
4. **Step 3**: Manual Terraform file updates + `terraform apply` (remove `_v1` key, JWKS serves only `_v2`)

### Terraform Dependency Management

Terraform's built-in dependency resolution ensures proper ordering:
- Lambda environment variables that reference KMS alias names create implicit dependencies
- KMS keys must be created before aliases can reference them
- Aliases must exist before environment variables can reference them
- Lambda deployments occur after all referenced resources are available

This eliminates the risk of environment variables referencing non-existent keys during deployment.

## Consequences

### Benefits

- **Zero downtime**: Both keys remain valid throughout the transition
- **Works with JWKS caching**: Uses environment variables instead of alias switching to control JWKS behavior
- **Single-day rotation**: Complete key rotation can be accomplished in one day
- **Clear separation**: Distinct aliases for JWKS serving vs signing operations
- **Safe rollback**: Can revert by updating environment variables back to old key version

### Trade-offs

- **Temporary dual-key state**: JWKS serves two keys during rotation
- **Manual environment variable management**: Requires updating lambda environment variables for each rotation
- **Versioned key proliferation**: Old versioned keys must be cleaned up after rotation
- **Additional alias complexity**: Requires three aliases instead of the original single alias approach

### Implementation Requirements

- Create third alias (`ipv_reverification_request_signing_key_current_alias`) for JWKS current key
- Update JWKS lambda to use both current and secondary alias environment variables
- Implement versioned key creation pattern in Terraform files
- Document manual Terraform file update process for each rotation step
- Establish process for cleanup of old versioned keys and aliases
- Ensure Terraform dependency declarations properly sequence resource creation

This approach ensures cryptographic security through regular key rotation while working within the constraints of JWKS endpoint caching and providing a clear, single-day rotation process.