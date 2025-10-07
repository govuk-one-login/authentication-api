package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchRefreshTokenException;

import java.util.List;
import java.util.Optional;

public class OrchRefreshTokenService extends BaseDynamoService<OrchRefreshTokenItem> {
    private static final Logger LOG = LogManager.getLogger(OrchAuthCodeService.class);
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";

    public OrchRefreshTokenService(ConfigurationService configurationService) {
        super(OrchRefreshTokenItem.class, "Refresh-Token", configurationService, true);
    }

    public OrchRefreshTokenService(
            DynamoDbClient dynamoDbClient, DynamoDbTable<OrchRefreshTokenItem> dynamoDbTable) {
        super(dynamoDbTable, dynamoDbClient);
    }

    public Optional<OrchRefreshTokenItem> getRefreshToken(String jwtId) {
        Optional<OrchRefreshTokenItem> orchRefreshToken = Optional.empty();
        try {
            orchRefreshToken = get(jwtId);
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException("Failed to get Orch refresh token from Dynamo", e);
        }

        if (orchRefreshToken.isEmpty()) {
            LOG.info("No Orch refresh token found with jwtId {}", jwtId);
            return Optional.empty();
        }

        var unusedOrchRefreshToken = orchRefreshToken.filter(s -> !s.getIsUsed());
        if (unusedOrchRefreshToken.isEmpty()) {
            LOG.info("Orch refresh token item with Jwt ID: {} has isUsed = true", jwtId);
            return Optional.empty();
        }
        return orchRefreshToken;
    }

    public Optional<OrchRefreshTokenItem> getRefreshTokenForAuthCode(String authCode) {
        List<OrchRefreshTokenItem> queryResults;
        try {
            queryResults = queryIndex(AUTH_CODE_INDEX, authCode);
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    "Failed to get Orch refresh token from Dynamo for auth code", e);
            return Optional.empty();
        }
        if (queryResults.isEmpty()) {
            LOG.info("No Orch refresh token found with authCode {}", authCode);
            return Optional.empty();
        }
        var unusedRefreshTokens = queryResults.stream().filter(s -> !s.getIsUsed()).toList();
        if (unusedRefreshTokens.isEmpty()) {
            LOG.info("Orch refresh token item with Auth Code: {} has isUsed = true", authCode);
            return Optional.empty();
        }
        return Optional.of(unusedRefreshTokens.get(0));
    }

    public void saveRefreshToken(
            String jwtId, String internalPairwiseSubjectId, String token, String authCode) {
        try {
            put(
                    new OrchRefreshTokenItem()
                            .withJwtId(jwtId)
                            .withInternalPairwiseSubjectId(internalPairwiseSubjectId)
                            .withToken(token)
                            .withAuthCode(authCode));
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    "Failed to save Orch refresh token item to Dynamo", e);
        }
    }

    public void deleteRefreshToken(String jwtId) {
        try {
            delete(jwtId);
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    "Failed to delete Orch refresh token item from Dynamo", e);
        }
    }

    private void logAndThrowOrchRefreshTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchRefreshTokenException(message);
    }
}
