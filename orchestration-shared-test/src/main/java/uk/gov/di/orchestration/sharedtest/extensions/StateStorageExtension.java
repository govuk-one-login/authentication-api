package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.time.Clock;
import java.util.Optional;

public class StateStorageExtension extends DynamoExtension implements AfterEachCallback {
    public static final String TABLE_NAME = "local-State-Storage";
    public static final String PREFIXED_SESSION_ID_FIELD = "PrefixedSessionId";
    private StateStorageService stateStorageService;
    private final ConfigurationService configurationService;

    public StateStorageExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        stateStorageService = new StateStorageService(configurationService, Clock.systemUTC());
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        stateStorageService = new StateStorageService(configurationService, Clock.systemUTC());
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, PREFIXED_SESSION_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createTableWithPartitionKey(TABLE_NAME, PREFIXED_SESSION_ID_FIELD);
        }
    }

    public void storeState(String prefixedSessionId, String state) {
        stateStorageService.storeState(prefixedSessionId, state);
    }

    public Optional<StateItem> getState(String prefixedSessionId) {
        return stateStorageService.getState(prefixedSessionId);
    }

    public void setClock(Clock clock) {
        stateStorageService = new StateStorageService(configurationService, clock);
    }
}
