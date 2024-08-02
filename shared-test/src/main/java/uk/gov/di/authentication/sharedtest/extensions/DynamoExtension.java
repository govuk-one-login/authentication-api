package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

import java.util.Map;
import java.util.Optional;

public abstract class DynamoExtension extends BaseAwsResourceExtension
        implements BeforeAllCallback {

    protected static final String ENVIRONMENT =
            System.getenv().getOrDefault("ENVIRONMENT", "local");

    protected DynamoDbClient dynamoDB;

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        createInstance();
    }

    public DynamoDbClient newDynamoClient() {
        return DynamoDbClient.builder()
                .endpointOverride(LOCALSTACK_ENDPOINT)
                .credentialsProvider(LOCALSTACK_CREDENTIALS_PROVIDER)
                .region(Region.of(REGION))
                .build();
    }

    protected void createInstance() {
        dynamoDB = newDynamoClient();
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
}
