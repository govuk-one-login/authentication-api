package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class StateStorageExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-State-Storage";
    public static final String PREFIXED_SESSION_ID = "PrefixedSessionId";
    private StateStorageService stateStorageService;
    private final ConfigurationService configurationService;

    public StateStorageExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        stateStorageService = new StateStorageService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        stateStorageService = new StateStorageService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, PREFIXED_SESSION_ID);
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createOrchSessionTable();
        }
    }

    private void createOrchSessionTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(PREFIXED_SESSION_ID)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(PREFIXED_SESSION_ID)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public void addStateToDynamo(String prefixedSessionId, State state) {
        stateStorageService.storeState(prefixedSessionId, state);
    }

    public Optional<State> getStateFromDyamo(String prefixedSessionId) {
        return stateStorageService.getState(prefixedSessionId);
    }
}
