package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.IDReverificationState;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class IDReverificationStateExtension extends DynamoExtension implements AfterEachCallback {
    public static final String TABLE_NAME = "local-id-reverification-state";
    private IDReverificationStateService idReverificationStateService;
    private final ConfigurationService configuration;
    public static final String AUTHENTICATION_STATE_FIELD = "AuthenticationState";

    public IDReverificationStateExtension() {
        createInstance();
        this.configuration = new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        idReverificationStateService = new IDReverificationStateService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, AUTHENTICATION_STATE_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createIDReverificationStateTable();
        }
    }

    private void createIDReverificationStateTable() {
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

    public Optional<IDReverificationState> getIDReverificationState() {
        return idReverificationStateService.get(AUTHENTICATION_STATE_FIELD);
    }

    public void store(String orchestrationRedirectUrl, String clientSessionId) {
        idReverificationStateService.store(
                AUTHENTICATION_STATE_FIELD, orchestrationRedirectUrl, clientSessionId);
    }
}
