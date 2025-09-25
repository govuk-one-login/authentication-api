package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.RpPublicKeyCache;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RpPublicKeyCacheService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class RpPublicKeyCacheExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-RpPublicKeyCache";
    public static final String CLIENT_ID_FIELD = "clientId";
    public static final String KEY_ID_FIELD = "keyId";

    private RpPublicKeyCacheService rpPublicKeyCacheService;
    private final ConfigurationService configuration;

    public RpPublicKeyCacheExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
                    @Override
                    public long getAccessTokenExpiry() {
                        return ttl;
                    }
                };
        rpPublicKeyCacheService = new RpPublicKeyCacheService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        rpPublicKeyCacheService = new RpPublicKeyCacheService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, CLIENT_ID_FIELD, Optional.of(KEY_ID_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createTableWithPartitionAndSortKey(TABLE_NAME, CLIENT_ID_FIELD, KEY_ID_FIELD);
        }
    }

    public Optional<RpPublicKeyCache> getRpPublicKeyCacheData(String clientId, String keyId) {
        return rpPublicKeyCacheService.getRpPublicKeyCacheData(clientId, keyId);
    }

    public void addRpPublicKeyCacheData(String clientId, String keyId, String publicKey) {
        rpPublicKeyCacheService.addRpPublicKeyCacheData(clientId, keyId, publicKey);
    }
}
