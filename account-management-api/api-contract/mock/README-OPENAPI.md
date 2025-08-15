# OpenAPI Specification Management

## Current Setup
The `openapi_v2.symlink.yaml` file in this directory is a **copy** of the source OpenAPI specification, not a symlink.

## Source of Truth
The canonical OpenAPI specification is located at:
```
../../../ci/terraform/account-management/openapi_v2.yaml
```

## Keeping in Sync
Due to Docker container limitations, imposter cannot follow symlinks outside the mounted directory. 

### Manual Sync
To update the mock with the latest API specification:
```bash
cp ../../../ci/terraform/account-management/openapi_v2.yaml openapi_v2.symlink.yaml
```

### Automated Sync
Use the provided script:
```bash
./sync-and-run.sh
```

## Recent Updates
- ✅ **Groovy script updated** to handle endpoints without `publicSubjectId` parameters
- ✅ **`/update-email` endpoint now works correctly** (returns 204 for success)
- ✅ **All error cases preserved** via REST plugin configuration
- ✅ **Imposter version updated** to 4.7.0 with improved compatibility

## Important Notes
- ⚠️ **Always sync before testing** to ensure mocks match the current API specification
- ⚠️ **This file will become stale** if the source specification is updated
- ✅ **Use the sync script** for consistent development workflow
- ✅ **All README.md HTTP examples now work correctly**
