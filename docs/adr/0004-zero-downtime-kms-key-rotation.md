# Zero-downtime KMS key rotation for signing keys

## Context

The authentication service uses AWS KMS keys to sign JWTs for MFA reset journeys). These keys need periodic rotation for security compliance, but the current system lacks a mechanism to rotate keys without service downtime.

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

We will implement a zero-downtime key rotation process using a main signing alias plus "versioned" aliases, working around JWKS caching limitations by using environment variable updates to control which keys the JWKS endpoint serves.

### Architecture

- **Main Signing Alias** (`ipv_reverification_request_signing_key_alias`): Always points to the current active key for signing operations
- **Versioned Aliases**: Individual aliases for each key version (`ipv_reverification_request_signing_key_v1_alias`, `ipv_reverification_request_signing_key_v2_alias`, etc.)

### Key Components

- **JWKS Lambda Environment Variables**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references current versioned alias for primary key
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` - references previous versioned alias for backward compatibility during the transition
- **Signing Lambda Environment Variable**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references main signing alias (not a "versioned" alias)
- **Versioned Keys**: Each key has a corresponding versioned alias (`_v1_alias`, `_v2_alias`, etc.)

### Process

#### Terraform

1. **Create New Versioned Key** (Single Terraform Deployment):
   - Create new "versioned" KMS key and a new versioned alias (e.g., `ipv_reverification_request_signing_key_v2` and `ipv_reverification_request_signing_key_v2_alias`)
   - Raise a PR / run `terraform apply`
   - **Result**: New versioned key and alias deployed to all environments.

2. **Update JWKS** (Single Terraform Deployment):
   - Update JWKS lambda environment variables, taking care to ensure the old key is still referenced in the same way:
     - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` → `_v2_alias` (alias for the new primary signing key)
     - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` → `_v1_alias` (alias for the old signing key for compatibility)
   - **Note:** We must ensure that this lambda has permissions to access the new "versioned" key
   - Raise a PR / run `terraform apply`
   - **Result**: JWKS serves both keys, signing continues with old key via main alias
   - **Note:** We MUST only use the "versioned" aliases for this lambda. If we use the main signing alias here, we could end up in a situation in step (2) where we are publishing the new "v2" key twice and breaking backwards compatibility during the key transition.
   - **Note:** This has been split out from step (1) for additional safety, to ensure the new alias resource we will be referencing in the "main alias" environment variable is guaranteed to be created

3. **Switch Signing to New Key** (Single Terraform Deployment):
   - Update the main signing alias' `target_key_id` argument to point to the new key: `ipv_reverification_request_signing_key_alias` → `_v2` key
     - Currently, the main signing alias is the `ipv_reverification_request_signing_key_alias` resource.
   - **Note:** We must ensure that any signing lambdas have permissions to access the new "versioned" key
   - Raise a PR / run `terraform apply`
   - **Result**: New lambda invocations sign using the new key, the JWKS still serves both keys to enable verification of either key during the transition period
   - **Note**: If this process is not automated, i.e. if we have to manually raise a PR, we should inform IPV that we are performing a rotation in case it causes any issues

4. **IPV to update their fallback signing public key**
   - IPV maintains a copy of our signing key JWK for use as a fallback in the case that they are unable to retrieve the key from our JWKS endpoint
   - Ask IPV to update their fallback to the new JWK being published on our JWKS endpoint. This is done manually at present.

5. **Stop Publishing Old Key** (Single Terraform Deployment):
   - Ideally, wait at least 15 minutes from the point that we started signing using the new key. This will give the opportunity for any verification using the old deprecated key to be completed
   - Update JWKS lambda environment variables to remove the deprecated alias value (taking care to ensure that no changes are made to the old key):
     - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_DEPRECATED_ALIAS` should be removed so the old key is no longer published
   - Raise a PR / run `terraform apply`
   - **Result**: The JWKS endpoint should now only serve a single key (the new signing key)

6. **Cleanup Old Key Resources** (Single Terraform Deployment, after external cache expiry):
   - Wait a small amount of time in case there are any issues related to the changes made as part of step (5) above
   - Delete old key and the versioned alias associated with this key (e.g., `_v1_alias`) (which shouldn't be referenced anywhere)
     - The old key should be marked for deletion
   - Raise a PR / run `terraform apply`

#### AWS CloudFormation

The new production infrastructure, making use of AWS CloudFormation, will require a new secret be added when a new "versioned" alias is added in the Terraform. This is due to the IAM policy requiring reference to the underlying key resource (not the alias). It would be unfeasible to use a single secret here as we will be supporting two different signing keys during the transition period. This is equivalent to the changes being made in the Terraform.

### Deployment Timeline

Note: We can likely reduce this timing by moving away from manual key rotation.

**Day 1 - Create Resources and Publish in JWKS Set:**

1. **Step 1**: Create new versioned key → Merge PR / run `terraform apply`
2. **Step 2**: Update JWKS environment variables → Merge PR / run `terraform apply`
3. **Wait**: Allow time for the new key to be picked up

**Day 2 - Switch to Sign With New Key, IPV to Update Their Fallback, Stop Publishing Old Key:** 4. **Step 3**: Switch the main signing alias to point to the new key → Merge PR / run `terraform apply` 5. **Step 4**: IPV to update their fallback signing key to the new key 6. **Wait**: Allow time for the key transition 7. **Step 5**: Stop publishing the old key 8. **Step 6**: Mark the old key resources for deletion

**Timeline**: Steps 1-2 can be done immediately, Steps 3-4 after a short wait, and Steps 5-6 after another short wait

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
- Inform IPV of the rotation
- Document manual rotation process for each step
- Establish cleanup procedures for old keys and aliases
- Ensure proper Terraform dependency ordering

This approach provides secure key rotation while working within JWKS caching constraints.
