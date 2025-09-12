package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;

import java.util.Optional;

public class OrchAccessTokenService extends BaseDynamoService<OrchAccessTokenItem> {
    private static final Logger LOG = LogManager.getLogger(OrchAuthCodeService.class);

    public OrchAccessTokenService(ConfigurationService configurationService) {
        super(OrchAccessTokenItem.class, "Access-Token", configurationService, true);
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

    public Optional<OrchAccessTokenItem> getAccessTokenForAuthCode(String authCode) {
        try {
            var items = queryIndex("authCode-index", authCode);
            if (items.isEmpty()) {
                LOG.info("No Orch access token found with authCode {}", authCode);
                return Optional.empty();
            }
            return Optional.of(items.get(0));
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(
                    "Failed to get Orch access token from Dynamo for auth code", e);
            return Optional.empty();
        }
    }

    public void generateAndSaveAccessToken(
            String clientId,
            String rpPairwiseId,
            String token,
            String internalPairwiseSubjectId,
            String clientSessionId,
            String authCode) {

        try {
            put(
                    new OrchAccessTokenItem()
                            .withClientId(clientId)
                            .withRpPairwiseId(rpPairwiseId)
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
