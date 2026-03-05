package uk.gov.di.accountdata.extensions;

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
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;

import java.net.URI;
import java.util.ArrayList;
import java.util.Map;

public class AuthenticatorExtension implements AfterEachCallback, BeforeAllCallback {

    public static final String AUTHENTICATOR_TABLE = "local-authenticator";
    public static final String PUBLIC_SUBJECT_ID_FIELD = "PublicSubjectID";
    public static final String SORT_KEY_FIELD = "SK";
    protected DynamoDbClient dynamoDB;
    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");

    @Override
    public void beforeAll(ExtensionContext context) {
        dynamoDB =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(REGION))
                        .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                        .build();

        createTables();
    }

    @Override
    public void afterEach(ExtensionContext context) {
        clearTable(dynamoDB, PUBLIC_SUBJECT_ID_FIELD, SORT_KEY_FIELD);
    }

    private void createTables() {
        boolean tableExists;
        try {
            dynamoDB.describeTable(
                    DescribeTableRequest.builder().tableName(AUTHENTICATOR_TABLE).build());
            tableExists = true;
        } catch (ResourceNotFoundException ignored) {
            tableExists = false;
        }
        if (!tableExists) {
            createAuthenticatorTable();
        }
    }

    private void createAuthenticatorTable() {
        ArrayList<AttributeDefinition> attributeDefinitions = new ArrayList<>();
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                        .attributeType("S")
                        .build());
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(SORT_KEY_FIELD)
                        .attributeType("S")
                        .build());

        ArrayList<KeySchemaElement> tableKeySchema = new ArrayList<>();
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                        .keyType(KeyType.HASH)
                        .build());
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(SORT_KEY_FIELD)
                        .keyType(KeyType.RANGE)
                        .build());

        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTHENTICATOR_TABLE)
                        .attributeDefinitions(attributeDefinitions)
                        .keySchema(tableKeySchema)
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();

        dynamoDB.createTable(request);
    }

    protected void clearTable(DynamoDbClient dynamoDB, String key, String sortKey) {
        var scanRequest = ScanRequest.builder().tableName(AUTHENTICATOR_TABLE).build();
        var result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.items()) {
            var keyMap = Map.of(key, item.get(key), sortKey, item.get(sortKey));
            dynamoDB.deleteItem(
                    DeleteItemRequest.builder().tableName(AUTHENTICATOR_TABLE).key(keyMap).build());
        }
    }
}
