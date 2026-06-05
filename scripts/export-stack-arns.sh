#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <stack-name> [region]" >&2
  exit 1
fi

STACK_NAME="$1"
REGION="${2:-eu-west-2}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ACCOUNT_NAME=$(aws iam list-account-aliases --query "AccountAliases[0]" --output text 2>/dev/null || echo "$ACCOUNT_ID")

get_arn() {
  local type="$1" physical_id="$2"

  case "$type" in
    AWS::Lambda::Function|AWS::Serverless::Function)
      aws lambda get-function-configuration --function-name "$physical_id" --region "$REGION" --query FunctionArn --output text 2>/dev/null || echo ""
      ;;
    AWS::IAM::Role)
      aws iam get-role --role-name "$physical_id" --query Role.Arn --output text 2>/dev/null || echo ""
      ;;
    AWS::IAM::ManagedPolicy)
      echo "$physical_id"  # PhysicalResourceId is already the ARN for managed policies
      ;;
    AWS::KMS::Key)
      aws kms describe-key --key-id "$physical_id" --region "$REGION" --query KeyMetadata.Arn --output text 2>/dev/null || echo ""
      ;;
    AWS::KMS::Alias)
      echo "arn:aws:kms:${REGION}:${ACCOUNT_ID}:${physical_id}"
      ;;
    AWS::Logs::LogGroup)
      echo "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${physical_id}"
      ;;
    AWS::Logs::MetricFilter|AWS::Logs::SubscriptionFilter)
      echo "N/A"  # These don't have standalone ARNs
      ;;
    AWS::CloudWatch::Alarm)
      echo "arn:aws:cloudwatch:${REGION}:${ACCOUNT_ID}:alarm:${physical_id}"
      ;;
    AWS::Lambda::Permission)
      echo "N/A"  # Permissions don't have ARNs
      ;;
    AWS::DynamoDB::Table|AWS::DynamoDB::GlobalTable)
      aws dynamodb describe-table --table-name "$physical_id" --region "$REGION" --query Table.TableArn --output text 2>/dev/null || echo ""
      ;;
    AWS::S3::Bucket)
      echo "arn:aws:s3:::${physical_id}"
      ;;
    AWS::EC2::SecurityGroup)
      echo "arn:aws:ec2:${REGION}:${ACCOUNT_ID}:security-group/${physical_id}"
      ;;
    AWS::Serverless::Api|AWS::ApiGateway::RestApi)
      echo "arn:aws:apigateway:${REGION}::/restapis/${physical_id}"
      ;;
    *)
      echo "$physical_id"
      ;;
  esac
}

echo "AccountName,AccountId,StackName,LogicalResourceId,ResourceType,ARN"

resources=$(aws cloudformation list-stack-resources --stack-name "$STACK_NAME" --region "$REGION" \
  --query "StackResourceSummaries[].{L:LogicalResourceId,P:PhysicalResourceId,T:ResourceType}" --output json)

echo "$resources" | jq -c '.[]' | while read -r row; do
  logical=$(echo "$row" | jq -r '.L')
  physical=$(echo "$row" | jq -r '.P')
  type=$(echo "$row" | jq -r '.T')

  arn=$(get_arn "$type" "$physical")
  echo "${ACCOUNT_NAME},${ACCOUNT_ID},${STACK_NAME},${logical},${type},${arn}"
done
