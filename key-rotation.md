# Key Rotation Process

## Overview

This document describes the zero-downtime key rotation process for KMS signing keys used in the authentication service. The process uses three KMS aliases and versioned keys to work around JWKS endpoint caching limitations.

## Architecture

### Key Components

- **Current Alias** (`ipv_reverification_request_signing_key_current_alias`): Points to the key currently served by JWKS endpoints
- **Secondary Alias** (`ipv_reverification_request_signing_key_secondary_alias`): Points to the secondary key served by JWKS endpoints
- **Signing Alias** (`ipv_reverification_request_signing_key_alias`): Points to the key used by signing lambda handlers
- **Versioned Keys**: Keys created with version suffixes (`_v1`, `_v2`, etc.)

### Environment Variables

- **JWKS Lambda Environment Variables**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references current alias
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_SECONDARY_ALIAS` - references secondary alias
- **Signing Lambda Environment Variable**:
  - `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` - references signing alias

## Key Rotation Process

| Step | Description | Terraform Changes | Deployment | Result |
|------|-------------|-------------------|------------|--------|
| **1** | **Create New Key & Update JWKS** | • Add `aws_kms_key.ipv_reverification_request_signing_key_v2`<br>• Update `current_alias` target to `_v2` key<br>• Update JWKS env var `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS` to reference `current_alias`<br>• Update JWKS env var `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_SECONDARY_ALIAS` to reference `secondary_alias` (pointing to `_v1`) | `terraform apply` | • JWKS serves both `_v1` and `_v2` keys<br>• Signing still uses `_v1` key<br>• Zero downtime |
| **2** | **Switch Signing to New Key** | • Update `signing_alias` target from `_v1` to `_v2` key | `terraform apply` | • JWKS serves both `_v1` and `_v2` keys<br>• Signing uses `_v2` key<br>• Zero downtime |
| **3** | **Remove Old Key** | • Remove JWKS env var `IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_SECONDARY_ALIAS`<br>• Remove `aws_kms_key.ipv_reverification_request_signing_key_v1`<br>• Remove any aliases pointing to `_v1` key | `terraform apply` | • JWKS serves only `_v2` key<br>• Signing uses `_v2` key<br>• Rotation complete |

## Detailed Terraform File Changes

### Step 1: Create New Key & Update JWKS

**File: `ci/terraform/oidc/ecc-signing-key.tf`**
```hcl
# Add new versioned key
resource "aws_kms_key" "ipv_reverification_request_signing_key_v2" {
  description              = "KMS signing key (ECC) for JARs sent from Authentication to IPV for MFA reset (v2)"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  policy = data.aws_iam_policy_document.ipv_reverification_request_signing_key_access_policy.json
}

# Update current alias to point to v2
resource "aws_kms_alias" "ipv_reverification_request_signing_key_current_alias" {
  name          = "alias/${var.environment}-ipv_reverification_request_signing_key_current"
  target_key_id = aws_kms_key.ipv_reverification_request_signing_key_v2.key_id
}

# Keep secondary alias pointing to v1
resource "aws_kms_alias" "ipv_reverification_request_signing_key_secondary_alias" {
  name          = "alias/${var.environment}-ipv_reverification_request_signing_key_secondary"
  target_key_id = aws_kms_key.ipv_reverification_request_signing_key.key_id  # v1 key
}
```

**File: `ci/terraform/oidc/mfa-reset-jar-jwk.tf`**
```hcl
handler_environment_variables = {
  ENVIRONMENT                                             = var.environment
  IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS           = aws_kms_alias.ipv_reverification_request_signing_key_current_alias.name
  IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_SECONDARY_ALIAS = aws_kms_alias.ipv_reverification_request_signing_key_secondary_alias.name
}
```

### Step 2: Switch Signing to New Key

**File: `ci/terraform/oidc/ecc-signing-key.tf`**
```hcl
# Update signing alias to point to v2
resource "aws_kms_alias" "ipv_reverification_request_signing_key_alias" {
  name          = "alias/${var.environment}-ipv_reverification_request_signing_key"
  target_key_id = aws_kms_key.ipv_reverification_request_signing_key_v2.key_id
}
```

### Step 3: Remove Old Key

**File: `ci/terraform/oidc/mfa-reset-jar-jwk.tf`**
```hcl
handler_environment_variables = {
  ENVIRONMENT                                             = var.environment
  IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS           = aws_kms_alias.ipv_reverification_request_signing_key_current_alias.name
  # Remove secondary alias reference
}
```

**File: `ci/terraform/oidc/ecc-signing-key.tf`**
```hcl
# Remove old key and secondary alias
# Delete: aws_kms_key.ipv_reverification_request_signing_key (v1)
# Delete: aws_kms_alias.ipv_reverification_request_signing_key_secondary_alias
```

## Deployment Commands

```bash
# Step 1: Create new key and update JWKS
terraform apply

# Step 2: Switch signing to new key  
terraform apply

# Step 3: Remove old key (after cache expiry)
terraform apply
```

## Key States During Rotation

| Step | Current Alias | Secondary Alias | Signing Alias | JWKS Keys | Signing Key |
|------|---------------|-----------------|---------------|-----------|-------------|
| **Initial** | `_v1` | N/A | `_v1` | 1 (`_v1`) | `_v1` |
| **Step 1** | `_v2` | `_v1` | `_v1` | 2 (`_v2`, `_v1`) | `_v1` |
| **Step 2** | `_v2` | `_v1` | `_v2` | 2 (`_v2`, `_v1`) | `_v2` |
| **Step 3** | `_v2` | N/A | `_v2` | 1 (`_v2`) | `_v2` |

## Terraform Dependency Guarantees

Terraform ensures proper resource creation order through implicit dependencies:
- KMS keys created before aliases reference them
- Aliases created before environment variables reference them  
- Lambda deployments occur after all referenced resources exist

This eliminates risk of referencing non-existent resources during deployment.

## Benefits

- **Zero downtime**: Both keys remain valid throughout the transition
- **Works with JWKS caching**: Uses environment variables instead of alias switching
- **Single-day rotation**: Complete key rotation can be accomplished in one day
- **Clear separation**: Distinct aliases for JWKS serving vs signing operations
- **Safe rollback**: Can revert by updating environment variables back to old key version