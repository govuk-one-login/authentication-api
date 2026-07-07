package uk.gov.di.accountmanagement.testsupport;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class AuthenticatorStoreExtension implements BeforeAllCallback, AfterEachCallback {

    private static final String TABLE_NAME = "local-authenticator";
    private static final String PUBLIC_SUBJECT_ID_FIELD = "PublicSubjectID";
    private static final String SORT_KEY_FIELD = "SK";
    private static final String REGION_VALUE =
            System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");

    private DynamoDbClient dynamoDB;

    @Override
    public void beforeAll(ExtensionContext context) {
        dynamoDB =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(REGION_VALUE))
                        .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                        .build();

        if (!tableExists()) {
            createTable();
        }
    }

    @Override
    public void afterEach(ExtensionContext context) {
        var scanResult = dynamoDB.scan(ScanRequest.builder().tableName(TABLE_NAME).build());
        for (Map<String, AttributeValue> item : scanResult.items()) {
            dynamoDB.deleteItem(
                    DeleteItemRequest.builder()
                            .tableName(TABLE_NAME)
                            .key(
                                    Map.of(
                                            PUBLIC_SUBJECT_ID_FIELD,
                                            item.get(PUBLIC_SUBJECT_ID_FIELD),
                                            SORT_KEY_FIELD,
                                            item.get(SORT_KEY_FIELD)))
                            .build());
        }
    }

    public void addMinimalPasskey(String publicSubjectId, String credentialId) {
        dynamoDB.putItem(
                PutItemRequest.builder()
                        .tableName(TABLE_NAME)
                        .item(
                                Map.of(
                                        PUBLIC_SUBJECT_ID_FIELD,
                                        AttributeValue.builder().s(publicSubjectId).build(),
                                        SORT_KEY_FIELD,
                                        AttributeValue.builder()
                                                .s("PASSKEY#" + credentialId)
                                                .build()))
                        .build());
    }

    public List<Map<String, AttributeValue>> getItemsForUser(String publicSubjectId) {
        var response =
                dynamoDB.query(
                        QueryRequest.builder()
                                .tableName(TABLE_NAME)
                                .keyConditionExpression("#pk = :pkValue")
                                .expressionAttributeNames(Map.of("#pk", PUBLIC_SUBJECT_ID_FIELD))
                                .expressionAttributeValues(
                                        Map.of(
                                                ":pkValue",
                                                AttributeValue.builder()
                                                        .s(publicSubjectId)
                                                        .build()))
                                .build());
        return response.items();
    }

    private boolean tableExists() {
        try {
            dynamoDB.describeTable(DescribeTableRequest.builder().tableName(TABLE_NAME).build());
            return true;
        } catch (ResourceNotFoundException ignored) {
            return false;
        }
    }

    private void createTable() {
        dynamoDB.createTable(
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                                        .keyType(KeyType.HASH)
                                        .build(),
                                KeySchemaElement.builder()
                                        .attributeName(SORT_KEY_FIELD)
                                        .keyType(KeyType.RANGE)
                                        .build())
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(SORT_KEY_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build());
    }
}
