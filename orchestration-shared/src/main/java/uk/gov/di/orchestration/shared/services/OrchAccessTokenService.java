package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;

import java.util.Optional;

public class OrchAccessTokenService extends BaseDynamoService<OrchAccessTokenItem> {
    private static final Logger LOG = LogManager.getLogger(OrchAuthCodeService.class);
    private final ConfigurationService configurationService;

    public OrchAccessTokenService(ConfigurationService configurationService) {
        super(OrchAccessTokenItem.class, "Access-Token", configurationService, true);
        this.configurationService = configurationService;
    }

    // Just for unit test
    public OrchAccessTokenService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<OrchAccessTokenItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
        this.configurationService = configurationService;
    }

    public Optional<OrchAccessTokenItem> getAccessToken(String clientId, String rpPairwiseId) {
        Optional<OrchAccessTokenItem> orchAccessToken = Optional.empty();
        try {
            orchAccessToken = get(clientId, rpPairwiseId);
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException("Failed to get Orch access token from Dynamo", e);
        }

        if (orchAccessToken.isEmpty()) {
            LOG.info(
                    "No Orch access token found with clientId {} and rpPairwiseId {}",
                    clientId,
                    rpPairwiseId);
        }
        return orchAccessToken;
    }

    public void generateAndSaveAccessToken(
            String clientId,
            String rpPairwiseId,
            String token,
            String internalPairwiseSubjectId,
            String clientSessionId,
            String authCode) {

        var accessToken =
                new OrchAccessTokenItem()
                        .withClientId(clientId)
                        .withRpPairwiseId(rpPairwiseId)
                        .withToken(token)
                        .withInternalPairwiseSubjectId(internalPairwiseSubjectId)
                        .withClientSessionId(clientSessionId)
                        .withAuthCode(authCode);
        storeAccessToken(accessToken);
    }

    public void storeAccessToken(OrchAccessTokenItem accessToken) {
        try {
            put(accessToken);
        } catch (Exception e) {
            LOG.error("Failed to save Orch access token item to Dynamo", e);
            throw new RuntimeException(e);
        }
    }

    private void logAndThrowOrchAccessTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new RuntimeException(message);
    }
}
