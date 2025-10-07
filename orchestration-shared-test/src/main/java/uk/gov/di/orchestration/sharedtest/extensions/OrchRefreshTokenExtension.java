package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchRefreshTokenService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

public class OrchRefreshTokenExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Refresh-Token";
    public static final String ORCH_REFRESH_TOKEN_ID_FIELD = "JwtId";
    private OrchRefreshTokenService orchRefreshTokenService;
    private final ConfigurationService configurationService;

    public OrchRefreshTokenExtension() {
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        orchRefreshTokenService = new OrchRefreshTokenService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, ORCH_REFRESH_TOKEN_ID_FIELD);
    }

    @Override
    protected void createTables() {
        createTableWithPartitionKey(
                TABLE_NAME,
                ORCH_REFRESH_TOKEN_ID_FIELD,
                createGlobalSecondaryIndex("AuthCodeIndex", "AuthCode"));
    }

    public void saveRefreshToken(
            String jwtId, String internalPairwiseSubjectId, String token, String authCode) {
        orchRefreshTokenService.saveRefreshToken(jwtId, internalPairwiseSubjectId, token, authCode);
    }

    public Optional<OrchRefreshTokenItem> getRefreshToken(String jwtId) {
        return orchRefreshTokenService.getRefreshToken(jwtId);
    }

    public List<OrchRefreshTokenItem> getRefreshTokensForAuthCode(String authCode) {
        return orchRefreshTokenService.getRefreshTokensForAuthCode(authCode);
    }
}
