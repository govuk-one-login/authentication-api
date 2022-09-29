package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

import java.net.URI;
import java.util.Map;

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
                        .credentialsProvider(DefaultCredentialsProvider.create())
                        .region(Region.of(REGION))
                        .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                        .build();

        createTables();
    }

    protected void createInstance() {
        dynamoDB =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.create())
                        .region(Region.of(REGION))
                        .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                        .build();

        createTables();
    }

    protected abstract void createTables();

    protected boolean tableExists(String tableName) {
        try {
            dynamoDB.describeTable(DescribeTableRequest.builder().tableName(tableName).build());
            return true;
        } catch (ResourceNotFoundException ignored) {
            return false;
        }
    }

    protected void clearDynamoTable(DynamoDbClient dynamoDB, String tableName, String key) {
        var scanRequest = ScanRequest.builder().tableName(tableName).build();
        ScanResponse result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.items()) {
            dynamoDB.deleteItem(
                    DeleteItemRequest.builder()
                            .tableName(tableName)
                            .key(Map.of(key, item.get(key)))
                            .build());
        }
    }
}
