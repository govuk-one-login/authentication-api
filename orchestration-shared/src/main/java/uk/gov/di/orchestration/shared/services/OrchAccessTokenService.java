package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;

import java.util.List;
import java.util.Optional;

public class OrchAccessTokenService extends BaseDynamoService<OrchAccessTokenItem> {
    private static final Logger LOG = LogManager.getLogger(OrchAccessTokenService.class);
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";

    public OrchAccessTokenService(ConfigurationService configurationService) {
        super(OrchAccessTokenItem.class, "Access-Token", configurationService, true);
    }

    public OrchAccessTokenService(
            DynamoDbClient dynamoDbClient, DynamoDbTable<OrchAccessTokenItem> dynamoDbTable) {
        super(dynamoDbTable, dynamoDbClient);
    }

    public Optional<OrchAccessTokenItem> getAccessToken(
            String clientAndRpPairwiseId, String authCode) {
        Optional<OrchAccessTokenItem> orchAccessToken = Optional.empty();
        try {
            orchAccessToken = get(clientAndRpPairwiseId, authCode);
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException("Failed to get Orch access token from Dynamo", e);
        }

        if (orchAccessToken.isEmpty()) {
            LOG.info(
                    "No Orch access token found for clientAndRpPairwiseId {}",
                    clientAndRpPairwiseId);
        }
        return orchAccessToken;
    }

    public List<OrchAccessTokenItem> getAccessTokensForClientAndRpPairwiseId(
            String clientAndRpPairwiseId) {
        List<OrchAccessTokenItem> orchAccessTokens = List.of();
        try {
            orchAccessTokens = queryTableStream(clientAndRpPairwiseId).toList();
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException("Failed to get Orch access tokens from Dynamo", e);
        }
        if (orchAccessTokens.isEmpty()) {
            LOG.info(
                    "No Orch access token found for clientAndRpPairwiseId {}",
                    clientAndRpPairwiseId);
        }
        return orchAccessTokens;
    }

    public Optional<OrchAccessTokenItem> getAccessTokenForAuthCode(String authCode) {
        try {
            var items = queryIndex(AUTH_CODE_INDEX, authCode);
            if (items.isEmpty()) {
                LOG.info("No Orch access token found");
                return Optional.empty();
            }
            return Optional.of(items.get(0));
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException("Failed to get Orch access token from Dynamo", e);
            return Optional.empty();
        }
    }

    public void saveAccessToken(
            String clientAndRpPairwiseId,
            String authCode,
            String token,
            String internalPairwiseSubjectId,
            String clientSessionId) {
        try {
            put(
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(clientAndRpPairwiseId)
                            .withToken(token)
                            .withInternalPairwiseSubjectId(internalPairwiseSubjectId)
                            .withClientSessionId(clientSessionId)
                            .withAuthCode(authCode));
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(
                    "Failed to save Orch access token item to Dynamo", e);
        }
    }

    private void logAndThrowOrchAccessTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchAccessTokenException(message);
    }
}
