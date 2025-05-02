package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class OrchSessionExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Orch-Session";
    public static final String SESSION_ID_FIELD = "SessionId";
    private OrchSessionService orchSessionService;
    private final ConfigurationService configurationService;

    public OrchSessionExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        orchSessionService = new OrchSessionService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        orchSessionService = new OrchSessionService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, SESSION_ID_FIELD);
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
                                        .attributeName(SESSION_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(SESSION_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public void addSession(OrchSessionItem orchSession) {
        orchSessionService.addSession(orchSession);
    }

    public void addClientSessionIdToSession(String clientSessionId, String sessionId) {
        orchSessionService.updateSession(
                orchSessionService
                        .getSession(sessionId)
                        .orElse(new OrchSessionItem(sessionId))
                        .addClientSession(clientSessionId));
    }

    public OrchSessionItem addOrUpdateSessionId(
            Optional<String> previousSessionId, String newSessionId) {
        return orchSessionService.addOrUpdateSessionId(previousSessionId, newSessionId);
    }

    public Optional<OrchSessionItem> getSession(String sessionId) {
        return orchSessionService.getSession(sessionId);
    }

    public void updateSession(OrchSessionItem sessionItem) {
        orchSessionService.updateSession(sessionItem);
    }
}
