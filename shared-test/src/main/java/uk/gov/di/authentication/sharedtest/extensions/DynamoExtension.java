package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ResourceNotFoundException;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Map;

public abstract class DynamoExtension implements BeforeAllCallback {

    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String ENVIRONMENT =
            System.getenv().getOrDefault("ENVIRONMENT", "local");
    protected static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");

    protected AmazonDynamoDB dynamoDB;

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        dynamoDB =
                AmazonDynamoDBClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(DYNAMO_ENDPOINT, REGION))
                        .build();

        createTables();
    }

    protected abstract void createTables();

    protected boolean tableExists(String tableName) {
        try {
            dynamoDB.describeTable(tableName);
            return true;
        } catch (ResourceNotFoundException ignored) {
            return false;
        }
    }

    protected void clearDynamoTable(AmazonDynamoDB dynamoDB, String tableName, String key) {
        ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
        ScanResult result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.getItems()) {
            dynamoDB.deleteItem(tableName, Map.of(key, item.get(key)));
        }
    }
}
