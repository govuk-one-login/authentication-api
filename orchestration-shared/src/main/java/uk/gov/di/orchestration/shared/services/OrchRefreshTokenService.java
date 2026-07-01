package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.model.UpdateItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchRefreshTokenException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class OrchRefreshTokenService extends BaseDynamoService<OrchRefreshTokenItem> {
    private static final Logger LOG = LogManager.getLogger(OrchRefreshTokenService.class);
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private final long timeToLive;
    private final NowHelper.NowClock nowClock;

    public OrchRefreshTokenService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public OrchRefreshTokenService(ConfigurationService configurationService, Clock clock) {
        super(OrchRefreshTokenItem.class, "Refresh-Token", configurationService, true);
        this.timeToLive = configurationService.getRefreshTokenExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public OrchRefreshTokenService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<OrchRefreshTokenItem> dynamoDbTable,
            ConfigurationService configurationService,
            Clock clock) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getRefreshTokenExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
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
        return markAuthCodeAsUsedIfAuthCodeUnused(unusedOrchRefreshToken.get());
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
            String jwtId,
            String internalPairwiseSubjectId,
            String token,
            String authCode,
            String clientSessionId) {
        try {
            var itemTtl =
                    nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS).toInstant().getEpochSecond();
            put(
                    new OrchRefreshTokenItem()
                            .withJwtId(jwtId)
                            .withInternalPairwiseSubjectId(internalPairwiseSubjectId)
                            .withToken(token)
                            .withAuthCode(authCode)
                            .withClientSessionId(clientSessionId)
                            .withTimeToLive(itemTtl));
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    "Failed to save Orch refresh token item to Dynamo", e);
        }
    }

    private Optional<OrchRefreshTokenItem> markAuthCodeAsUsedIfAuthCodeUnused(
            OrchRefreshTokenItem orchRefreshTokenItem) {
        var item = orchRefreshTokenItem.withIsUsed(true);
        Expression conditionExpression =
                Expression.builder()
                        .expression("IsUsed = :false")
                        .expressionValues(
                                Collections.singletonMap(
                                        ":false", AttributeValue.builder().bool(false).build()))
                        .build();

        UpdateItemEnhancedRequest<OrchRefreshTokenItem> enhancedRequest =
                UpdateItemEnhancedRequest.builder(OrchRefreshTokenItem.class)
                        .item(item)
                        .conditionExpression(conditionExpression)
                        .build();

        try {
            update(enhancedRequest);
        } catch (ConditionalCheckFailedException e) {
            LOG.info("Orch refresh token item with Jwt ID: {} has isUsed = true", item.getJwtId());
            return Optional.empty();
        } catch (Exception e) {
            logAndThrowOrchRefreshTokenException(
                    String.format(
                            "Failed to mark refresh token as used. Token jwt: %s",
                            orchRefreshTokenItem.getJwtId()),
                    e);
        }
        return Optional.of(item);
    }

    private void logAndThrowOrchRefreshTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchRefreshTokenException(message);
    }
}
