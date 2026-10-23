package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;

import java.util.Optional;

public class IADCircuitBreakerStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-iad-circuit-breaker";
    public static final String PARTITION_KEY_FIELD = "pk";
    public static final String SORT_KEY_FIELD = "datetime";

    public IADCircuitBreakerStoreExtension() {
        createInstance();
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, PARTITION_KEY_FIELD, Optional.of(SORT_KEY_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createCircuitBreakerTable();
        }
    }

    private void createCircuitBreakerTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(PARTITION_KEY_FIELD)
                                        .build(),
                                KeySchemaElement.builder()
                                        .keyType(KeyType.RANGE)
                                        .attributeName(SORT_KEY_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(PARTITION_KEY_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(SORT_KEY_FIELD)
                                        .attributeType(ScalarAttributeType.N)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }
}
