package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class OrchAccessTokenExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Access-Token";
    public static final String NEW_TABLE_NAME = "local-Orch-Access-Token";
    public static final String CLIENT_AND_RP_PAIRWISE_ID_FIELD = "ClientAndRpPairwiseId";
    private static final String AUTH_CODE_FIELD = "AuthCode";
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private OrchAccessTokenService orchAccessTokenService;
    private final ConfigurationService configurationService;

    public OrchAccessTokenExtension() {
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        orchAccessTokenService = new OrchAccessTokenService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(
                dynamoDB,
                TABLE_NAME,
                CLIENT_AND_RP_PAIRWISE_ID_FIELD,
                Optional.of(AUTH_CODE_FIELD));
        clearDynamoTable(
                dynamoDB,
                NEW_TABLE_NAME,
                CLIENT_AND_RP_PAIRWISE_ID_FIELD,
                Optional.of(AUTH_CODE_FIELD));
    }

    @Override
    protected void createTables() {
        createTableWithPartitionAndSortKey(
                TABLE_NAME,
                CLIENT_AND_RP_PAIRWISE_ID_FIELD,
                AUTH_CODE_FIELD,
                createGlobalSecondaryIndex(AUTH_CODE_INDEX, AUTH_CODE_FIELD));
        createTableWithPartitionAndSortKey(
                NEW_TABLE_NAME,
                CLIENT_AND_RP_PAIRWISE_ID_FIELD,
                AUTH_CODE_FIELD,
                createGlobalSecondaryIndex(AUTH_CODE_INDEX, AUTH_CODE_FIELD));
    }

    public void saveAccessToken(
            String clientAndRpPairwiseId,
            String authCode,
            String token,
            String internalPairwiseSubjectId,
            String clientSessionId) {
        orchAccessTokenService.saveAccessToken(
                clientAndRpPairwiseId, authCode, token, internalPairwiseSubjectId, clientSessionId);
    }

    public Optional<OrchAccessTokenItem> getAccessToken(
            String clientAndRpPairwiseId, String authCode) {
        return orchAccessTokenService.getAccessToken(clientAndRpPairwiseId, authCode);
    }

    public Optional<OrchAccessTokenItem> getAccessTokenForAuthCode(String authCode) {
        return orchAccessTokenService.getAccessTokenForAuthCode(authCode);
    }
}
