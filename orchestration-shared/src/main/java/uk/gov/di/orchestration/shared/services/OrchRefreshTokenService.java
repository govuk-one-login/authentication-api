package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchRefreshTokenException;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class OrchRefreshTokenService extends BaseDynamoService<OrchRefreshTokenItem> {
    private static final Logger LOG = LogManager.getLogger(OrchRefreshTokenService.class);
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
        var refreshToken = markTokenAsUsed(unusedOrchRefreshToken.get());
        return Optional.of(refreshToken);
    }

    public List<OrchRefreshTokenItem> getRefreshTokensForAuthCode(String authCode) {
        List<OrchRefreshTokenItem> refreshTokens = new ArrayList<>();
        try {
            refreshTokens = queryIndex(AUTH_CODE_INDEX, authCode);
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    "Failed to get Orch refresh tokens from Dynamo for auth code", e);
        }
        if (refreshTokens.isEmpty()) {
            LOG.info("No Orch refresh tokens found with authCode {}", authCode);
            return List.of();
        }
        return refreshTokens;
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

    private OrchRefreshTokenItem markTokenAsUsed(OrchRefreshTokenItem orchRefreshTokenItem) {
        var item = orchRefreshTokenItem.withIsUsed(true);
        try {
            update(item);
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    "Failed to mark refresh token as used. Token jwt: "
                            + orchRefreshTokenItem.getJwtId(),
                    e);
        }
        return item;
    }

    private void logAndThrowOrchRefreshTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchRefreshTokenException(message);
    }
}
