#!/bin/bash
# delete-all-items.sh
# Deletes all items from a DynamoDB table.
# WARNING: This is irreversible.

set -euo pipefail

TABLE_NAME="${1:?Usage: $0 <table-name> [region]}"
REGION="${2:-eu-west-2}"

echo "⚠️  WARNING: This will delete ALL items from table '$TABLE_NAME' in region '$REGION'."
echo "Press Ctrl+C to cancel, or Enter to continue..."
read -r

# Get the key schema for the table
KEY_SCHEMA=$(aws dynamodb describe-table \
  --table-name "$TABLE_NAME" \
  --region "$REGION" \
  --query "Table.KeySchema[].AttributeName" \
  --output text)

KEY_ATTRS=$(echo "$KEY_SCHEMA" | tr '\t' ',')
echo "Key attributes: $KEY_ATTRS"

# Build projection expression
PROJECTION=$(echo "$KEY_ATTRS" | sed 's/,/, /g')

TOTAL_DELETED=0
LAST_EVALUATED_KEY=""

while true; do
  # Scan for items (just the keys)
  if [ -z "$LAST_EVALUATED_KEY" ]; then
    SCAN_RESULT=$(aws dynamodb scan \
      --table-name "$TABLE_NAME" \
      --region "$REGION" \
      --projection-expression "$PROJECTION" \
      --max-items 25 \
      --output json)
  else
    SCAN_RESULT=$(aws dynamodb scan \
      --table-name "$TABLE_NAME" \
      --region "$REGION" \
      --projection-expression "$PROJECTION" \
      --max-items 25 \
      --starting-token "$LAST_EVALUATED_KEY" \
      --output json)
  fi

  ITEM_COUNT=$(echo "$SCAN_RESULT" | jq '.Items | length')

  if [ "$ITEM_COUNT" -eq 0 ]; then
    echo "No more items to delete."
    break
  fi

  # Build batch-write delete requests
  DELETE_REQUESTS=$(echo "$SCAN_RESULT" | jq -c '[.Items[] | {DeleteRequest: {Key: .}}]')

  # Execute batch write
  aws dynamodb batch-write-item \
    --region "$REGION" \
    --request-items "{\"$TABLE_NAME\": $DELETE_REQUESTS}" \
    --output json > /dev/null

  TOTAL_DELETED=$((TOTAL_DELETED + ITEM_COUNT))
  echo "Deleted $ITEM_COUNT items (total: $TOTAL_DELETED)"

  # Check for more items
  LAST_EVALUATED_KEY=$(echo "$SCAN_RESULT" | jq -r '.NextToken // empty')
  if [ -z "$LAST_EVALUATED_KEY" ]; then
    # Run another scan to check if there are still items
    CHECK=$(aws dynamodb scan \
      --table-name "$TABLE_NAME" \
      --region "$REGION" \
      --select COUNT \
      --max-items 1 \
      --output json)
    REMAINING=$(echo "$CHECK" | jq '.Count')
    if [ "$REMAINING" -eq 0 ]; then
      break
    fi
    LAST_EVALUATED_KEY=""
  fi
done

echo "✅ Done. Deleted $TOTAL_DELETED items total from '$TABLE_NAME'."
