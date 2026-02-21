# Utils Stack Migration Notes

This document tracks changes made during the migration from Terraform to CloudFormation for the utils stack.

## Date: 2026-02-09

## Changes Made to Enable Deployment

### 1. Removed Utils Lambda Signing Profiles from Non-Utils Sections

**File**: `scripts/dev-samconfig.toml`

**Issue**: Utils Lambda signing profiles were incorrectly added to ALL samconfig sections (dev, authdev1-3, authdevam, authdev1-3am, devstubs, authdev1-3stubs).

**Action**: Removed 8 utils Lambda function signing profiles from 12 non-utils sections. Signing profiles now ONLY exist in:

- `devutils`
- `authdev1utils`
- `authdev2utils`
- `authdev3utils`

**Functions affected**:

- AccountMetricsLambda
- BulkTestUserCreateLambda
- BulkTestUserDeleteLambda
- BulkUserEmailAudienceLoaderLambda
- BulkUserEmailSendLambda
- CommonPasswordsUpdateLambda
- EmailCheckResultsWriterLambda
- MfaMethodAnalysisLambda

### 2. Fixed VPC Security Group Export Name

**File**: `ci/cloudformation/utils/lambda-functions.yaml`

**Issue**: Template used incorrect export name `vpc-AllowAwsServiceAccessSecurityGroupId`

**Action**: Updated to correct export name `vpc-AWSServicesEndpointSecurityGroupId` (discovered via AWS CLI query using profile `di-authentication-development-admin`)

**Changed in**: All VPC-enabled Lambda functions (AccountMetrics, CommonPasswordsUpdate, MfaMethodAnalysis)

### 3. S3 Buckets - Changed to Use `-utils-` Prefix

**Files**:

- `ci/cloudformation/utils/s3-buckets.yaml`
- `ci/cloudformation/utils/iam-roles.yaml`

**Issue**: S3 buckets already exist from Terraform with these names:

- `${environment}-bulk-test-user-bucket`
- `${environment}-common-passwords-bucket`
- `${environment}-utils-lambda-source-*` (with random suffix)

**Action**: CloudFormation now creates NEW buckets with `-utils-` prefix to avoid clashes:

- `${Environment}-utils-bulk-test-user-bucket`
- `${Environment}-utils-common-passwords-bucket`
- `${Environment}-utils-lambda-source-bucket`

**Features**: All buckets include:

- Versioning enabled
- KMS encryption (aws/s3)
- SSL-only bucket policy
- Public access blocked
- Exports for bucket name and ARN

**IAM Policies Updated**: All IAM policies now reference the new bucket names with `-utils-` prefix.

**Rationale**: Allows CloudFormation and Terraform buckets to coexist during migration. Terraform buckets can be decommissioned after data migration.

### 4. Added MainKmsKey for CloudWatch Logs Encryption

**Files**:

- `ci/cloudformation/utils/parent.yaml`
- `ci/cloudformation/utils/lambda-functions.yaml`

**Issue**: Initial approach removed all log groups due to KMS key issues.

**Action**: Mirrored account-management pattern:

- Added `MainKmsKey` and `MainKmsKeyAlias` resources to `parent.yaml`
- Updated all 8 log group resources to use `KmsKeyId: !GetAtt MainKmsKey.Arn`
- Added `LoggingConfig: LogGroup: !Ref <LogGroupName>` to each Lambda function
- Subscription filters reference log groups using `!Ref`

**Functions affected**: All 8 Lambda functions now have explicit log groups with proper KMS encryption

### 5. Changed Lambda CodeUri to Local Path

**File**: `ci/cloudformation/utils/lambda-functions.yaml`

**Issue**: Lambda functions tried to load code from non-existent S3 location: `s3://authdev1-source-code-bucket/utils.zip`

**Action**: Changed all 8 Lambda functions to use local path: `./utils/build/distributions/utils.zip` (mirroring account-management pattern)

**Rationale**: SAM CLI packages local files during deployment. The actual S3 bucket is `authdev1-utils-pipeline-githubartifactsourcebucket-j4wxvzocetsq` but doesn't contain utils.zip.

### 6. Disabled EmailCheckResultsEventSourceMapping

**File**: `ci/cloudformation/utils/lambda-functions.yaml`

**Issue**: EmailCheckResultsWriterLambda tried to connect to non-existent SQS queue: `authdev1-email-check-results-queue`

**Investigation Findings**:

- Queue is NOT created in any CloudFormation stack
- Queue is NOT created in Terraform (not in `ci/terraform/shared/sqs.tf`)
- Variables exist in `ci/terraform/utils/variables.tf` but are never populated:
  - `email_check_results_sqs_queue_arn`
  - `email_check_results_sqs_queue_encryption_key_arn`
- EventSourceMapping exists in Terraform (`ci/terraform/utils/email_check_results_writer_lambda.tf`) but references non-existent variables
- Only the DynamoDB table `email-check-result` and KMS encryption policy exist

**Action**: Commented out `EmailCheckResultsEventSourceMapping` resource (lines 600-611) with explanatory note.

**Impact**: Lambda function will be created but won't have SQS trigger until queue infrastructure is created.

## Resources Managed by Terraform (Not Migrated)

1. **S3 Buckets**:
   - `authdev1-bulk-test-user-bucket`
   - `authdev1-common-passwords-bucket`
   - `authdev1-utils-lambda-source-*`

2. **SQS Queue** (doesn't exist yet):
   - `email-check-results-queue` - needs to be created in Terraform shared stack

## AWS Profile Used

- **Profile**: `di-authentication-development-admin`
- **Note**: Do NOT use `di-auth-*` profiles (old accounts being migrated away from)

## Deployment Command

```bash
sam deploy \
  --config-file scripts/dev-samconfig.toml \
  --config-env authdev1utils \
  --profile di-authentication-development-admin
```

## Next Steps

1. Complete deployment to authdev1
2. Verify all Lambda functions are created successfully
3. Test Lambda function invocations
4. Verify CloudWatch logs and Splunk forwarding
5. Consider creating `email-check-results-queue` in Terraform shared stack if needed
6. Document any additional differences or issues

## References

- Account-management stack patterns: `ci/cloudformation/account-management/`
- Terraform shared SQS: `ci/terraform/shared/sqs.tf`
- Terraform shared outputs: `ci/terraform/shared/outputs.tf`
