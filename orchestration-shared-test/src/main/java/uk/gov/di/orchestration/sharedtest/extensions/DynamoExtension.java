package uk.gov.di.orchestration.sharedtest.extensions;

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
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public abstract class DynamoExtension extends BaseAwsResourceExtension
        implements BeforeAllCallback {

    protected static final String ENVIRONMENT =
            System.getenv().getOrDefault("ENVIRONMENT", "local");
    protected static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");

    protected DynamoDbClient dynamoDB;

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        dynamoDB =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(REGION))
                        .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                        .build();

        createTables();
    }

    protected void createInstance() {
        dynamoDB =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(REGION))
                        .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                        .build();

        createTables();
    }

    protected abstract void createTables();

    private boolean tableExists(String tableName) {
        try {
            dynamoDB.describeTable(DescribeTableRequest.builder().tableName(tableName).build());
            return true;
        } catch (ResourceNotFoundException ignored) {
            return false;
        }
    }

    protected void clearDynamoTable(DynamoDbClient dynamoDB, String tableName, String key) {
        clearDynamoTable(dynamoDB, tableName, key, Optional.empty());
    }

    protected void clearDynamoTable(
            DynamoDbClient dynamoDB, String tableName, String key, Optional<String> sortKey) {
        var scanRequest = ScanRequest.builder().tableName(tableName).build();
        ScanResponse result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.items()) {
            Map<String, AttributeValue> keyMap =
                    sortKey.map(sk -> Map.of(key, item.get(key), sk, item.get(sk)))
                            .orElse(Map.of(key, item.get(key)));
            dynamoDB.deleteItem(
                    DeleteItemRequest.builder().tableName(tableName).key(keyMap).build());
        }
    }

    protected void createTableWithPartitionKey(
            String tableName,
            String partitionKeyField,
            GlobalSecondaryIndex... globalSecondaryIndices) {
        createTable(tableName, partitionKeyField, Optional.empty(), globalSecondaryIndices);
    }

    protected void createTableWithPartitionAndSortKey(
            String tableName,
            String partitionKeyField,
            String sortKey,
            GlobalSecondaryIndex... globalSecondaryIndices) {
        createTable(tableName, partitionKeyField, Optional.of(sortKey), globalSecondaryIndices);
    }

    private void createTable(
            String tableName,
            String partitionKeyField,
            Optional<String> sortKey,
            GlobalSecondaryIndex... globalSecondaryIndices) {
        if (tableExists(tableName)) {
            return;
        }
        var keySchemaElements = new ArrayList<KeySchemaElement>();
        keySchemaElements.add(
                KeySchemaElement.builder()
                        .keyType(KeyType.HASH)
                        .attributeName(partitionKeyField)
                        .build());
        sortKey.ifPresent(
                s ->
                        keySchemaElements.add(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.RANGE)
                                        .attributeName(s)
                                        .build()));

        var attributeDefinitions = new HashSet<AttributeDefinition>();
        attributeDefinitions.add(stringAttribute(partitionKeyField));
        sortKey.ifPresent(s -> attributeDefinitions.add(stringAttribute(s)));
        var requestBuilder =
                CreateTableRequest.builder()
                        .tableName(tableName)
                        .keySchema(keySchemaElements)
                        .billingMode(BillingMode.PAY_PER_REQUEST);
        if (globalSecondaryIndices.length > 0) {
            // Add all global index keys to attribute definitions
            Stream.of(globalSecondaryIndices)
                    .map(GlobalSecondaryIndex::keySchema)
                    .flatMap(List::stream)
                    .map(KeySchemaElement::attributeName)
                    .map(DynamoExtension::stringAttribute)
                    .forEach(attributeDefinitions::add);
            requestBuilder.globalSecondaryIndexes(globalSecondaryIndices);
        }
        requestBuilder.attributeDefinitions(attributeDefinitions);
        dynamoDB.createTable(requestBuilder.build());
    }

    protected GlobalSecondaryIndex createGlobalSecondaryIndex(
            String indexName, String partitionKey) {
        return GlobalSecondaryIndex.builder()
                .indexName(indexName)
                .keySchema(
                        KeySchemaElement.builder()
                                .attributeName(partitionKey)
                                .keyType(KeyType.HASH)
                                .build())
                .projection(t -> t.projectionType(ProjectionType.ALL))
                .build();
    }

    private static AttributeDefinition stringAttribute(String attributeName) {
        return AttributeDefinition.builder()
                .attributeName(attributeName)
                .attributeType(ScalarAttributeType.S)
                .build();
    }
}
