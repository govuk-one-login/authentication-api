#!/bin/bash
# Sync OpenAPI spec and run imposter

echo "Syncing OpenAPI specification..."
# Copy the latest OpenAPI spec from source
cp ../../../ci/terraform/account-management/openapi_v2.yaml openapi_v2.symlink.yaml

echo "Starting imposter with updated configuration..."
echo "Note: Groovy script updated to handle endpoints without publicSubjectId parameters"

# Run imposter
imposter up
