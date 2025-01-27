#!/bin/bash

echo "Building jars"
# Must use shadowJar to build jar with dependencies
./gradlew clean shadowJar

echo "Starting localstack with Docker Compose"
docker-compose -f docker-compose.ipv-stub.yml down
docker-compose -f docker-compose.ipv-stub.yml up -d

echo "Waiting for LocalStack..."
while ! awslocal lambda list-functions; do
  echo "LocalStack is not ready yet. Retrying in 3 seconds..."
  sleep 1
done

echo "LocalStack is ready!"

echo "Creating S3 bucket..."
awslocal s3 mb s3://mfa-reset-authorize-bucket

# Must upload jar to S3 to get around lambda size maximum
echo "Uploading ZIP to S3..."
awslocal s3api put-object \
    --bucket mfa-reset-authorize-bucket \
    --key lambdas/frontend-api-all.jar \
    --body ./frontend-api/build/libs/frontend-api-all.jar

echo "Creating lambdas..."
awslocal lambda create-function \
    --region "eu-west-2" \
    --role arn:aws:iam::123456789012:role/MyPlaceholderRole \
    --function-name mfa-reset-authorize \
    --runtime java17 \
    --code S3Bucket=mfa-reset-authorize-bucket,S3Key=lambdas/frontend-api-all.jar \
    --handler uk.gov.di.authentication.frontendapi.lambda.MfaResetAuthorizeHandler::handleRequest \
    --environment file://ipv-env.json

MFA_RESET_AUTHORIZE_ARN=$(awslocal lambda get-function --function-name mfa-reset-authorize --query 'Configuration.FunctionArn' --output text)

echo "Creating MFA Reset API..."

API_ID=$(awslocal apigateway create-rest-api \
    --name mfa-reset-api \
    --description "API for MFA reset with IPV functionality" \
    --query 'id' --output text)

REQUEST_MODEL_NAME="MfaResetAuthorizeRequest"

ROOT_RESOURCE_ID=$(awslocal apigateway get-resources --rest-api-id "${API_ID}" --query 'items[0].id' --output text)

AUTHORIZE_RESOURCE_ID=$(awslocal apigateway create-resource \
    --rest-api-id "${API_ID}" \
    --parent-id "${ROOT_RESOURCE_ID}" \
    --path-part authorize \
    --query 'id' --output text)

awslocal apigateway create-model \
    --rest-api-id "${API_ID}" \
    --name ${REQUEST_MODEL_NAME} \
    --description "Request model for MFA reset authorization" \
    --content-type "application/json" \
    --schema '{
        "type": "object",
        "properties": {
            "email": {
                "type": "string"
            },
            "orchestrationRedirectUrl": {
                "type": "string"
            }
        }
    }'

awslocal apigateway put-method \
    --rest-api-id "${API_ID}" \
    --resource-id "${AUTHORIZE_RESOURCE_ID}" \
    --http-method POST \
    --authorization-type NONE \
    --request-models '{"application/json": "'${REQUEST_MODEL_NAME}'"}'

awslocal apigateway put-integration \
    --rest-api-id "${API_ID}" \
    --resource-id "${AUTHORIZE_RESOURCE_ID}" \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/"${MFA_RESET_AUTHORIZE_ARN}"/invocations

awslocal apigateway create-deployment \
    --rest-api-id "${API_ID}" \
    --stage-name dev

aws ssm put-parameter \
 --endpoint-url http://localhost:4566 \
 --name localstack-redis_key-redis-master-host \
 --value "localhost" \
 --type String

aws ssm put-parameter \
 --endpoint-url http://localhost:4566 \
 --name localstack-redis_key-redis-tls \
 --value "false" \
 --type String

aws ssm put-parameter \
--endpoint-url http://localhost:4566 \
--name localstack-redis_key-redis-port \
--value "6379" \
--type String

echo "REST API ID: ${API_ID}"

echo "Deployment complete!"
