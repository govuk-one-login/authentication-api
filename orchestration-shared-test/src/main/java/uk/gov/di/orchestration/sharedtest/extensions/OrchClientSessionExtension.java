package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.time.Clock;
import java.util.Optional;

public class OrchClientSessionExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Client-Session";
    public static final String CLIENT_SESSION_ID_FIELD = "ClientSessionId";
    private OrchClientSessionService orchClientSessionService;
    private final ConfigurationService configurationService;

    public OrchClientSessionExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        orchClientSessionService = new OrchClientSessionService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        orchClientSessionService = new OrchClientSessionService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, CLIENT_SESSION_ID_FIELD);
    }

    @Override
    protected void createTables() {
        createTableWithPartitionKey(TABLE_NAME, CLIENT_SESSION_ID_FIELD);
    }

    public void storeClientSession(OrchClientSessionItem clientSession) {
        orchClientSessionService.storeClientSession(clientSession);
    }

    public void updateStoredClientSession(OrchClientSessionItem clientSession) {
        orchClientSessionService.updateStoredClientSession(clientSession);
    }

    public Optional<OrchClientSessionItem> getClientSession(String clientSessionId) {
        return orchClientSessionService.getClientSession(clientSessionId);
    }

    public void deleteStoredClientSession(String clientSessionId) {
        orchClientSessionService.deleteStoredClientSession(clientSessionId);
    }

    public void setClock(Clock clock) {
        orchClientSessionService = new OrchClientSessionService(configurationService, clock);
    }
}
