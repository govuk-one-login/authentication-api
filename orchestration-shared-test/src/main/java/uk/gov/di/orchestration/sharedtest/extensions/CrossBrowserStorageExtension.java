package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.CrossBrowserItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserStorageService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class CrossBrowserStorageExtension extends DynamoExtension implements AfterEachCallback {
    public static final String TABLE_NAME = "local-Cross-Browser";
    public static final String STATE_FIELD = "State";
    private CrossBrowserStorageService crossBrowserStorageService;
    private final ConfigurationService configurationService;

    public CrossBrowserStorageExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        crossBrowserStorageService = new CrossBrowserStorageService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        crossBrowserStorageService = new CrossBrowserStorageService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, STATE_FIELD);
    }

    @Override
    protected void createTables() {
        createTableWithPartitionKey(TABLE_NAME, STATE_FIELD);
    }

    public void storeItem(CrossBrowserItem item) {
        crossBrowserStorageService.storeItem(item);
    }

    public Optional<String> getClientSessionIdFromState(State state) {
        return crossBrowserStorageService.getClientSessionId(state);
    }
}
