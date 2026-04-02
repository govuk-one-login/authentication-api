package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;

public class AMCStateExtension extends DynamoExtension implements AfterEachCallback {
    public static final String TABLE_NAME = "local-amc-state";
    public static final String AUTHENTICATION_STATE_FIELD = "AuthenticationState";
    private final DynamoAmcStateService dynamoAmcStateService;

    public AMCStateExtension() {
        createInstance();
        dynamoAmcStateService = new DynamoAmcStateService(ConfigurationService.getInstance());
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, AUTHENTICATION_STATE_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createAMCStateTable();
        }
    }

    private void createAMCStateTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(AUTHENTICATION_STATE_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(AUTHENTICATION_STATE_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public void store(String state, String clientSessionId) {
        dynamoAmcStateService.store(state, clientSessionId);
    }
}
