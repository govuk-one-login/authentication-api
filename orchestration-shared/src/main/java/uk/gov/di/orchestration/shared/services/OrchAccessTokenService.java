package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class OrchAccessTokenService {
    private static final Logger LOG = LogManager.getLogger(OrchAccessTokenService.class);
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private static final String FAILED_TO_GET_ACCESS_TOKEN_FROM_DYNAMO_ERROR =
            "Failed to get Orch access token from Dynamo";
    private static final int TIME_REMAINING_BUFFER_IN_MILLISECONDS = 10000;

    private final BaseDynamoService<OrchAccessTokenItem> oldOrchAccessTokenService;
    private final BaseDynamoService<OrchAccessTokenItem> newOrchAccessTokenService;
    private final long timeToLive;
    private final NowHelper.NowClock nowClock;

    public OrchAccessTokenService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public OrchAccessTokenService(ConfigurationService configurationService, Clock clock) {
        oldOrchAccessTokenService =
                new BaseDynamoService<>(
                        OrchAccessTokenItem.class, "Access-Token", configurationService, true);
        newOrchAccessTokenService =
                new BaseDynamoService<>(
                        OrchAccessTokenItem.class, "Orch-Access-Token", configurationService, true);
        this.timeToLive = configurationService.getAccessTokenExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public OrchAccessTokenService(
            BaseDynamoService<OrchAccessTokenItem> oldService,
            BaseDynamoService<OrchAccessTokenItem> newService,
            ConfigurationService configurationService,
            Clock clock) {
        this.oldOrchAccessTokenService = oldService;
        this.newOrchAccessTokenService = newService;
        this.timeToLive = configurationService.getAccessTokenExpiry();
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public Optional<OrchAccessTokenItem> getAccessToken(
            String clientAndRpPairwiseId, String authCode) {
        Optional<OrchAccessTokenItem> orchAccessToken = Optional.empty();
        try {
            orchAccessToken = oldOrchAccessTokenService.get(clientAndRpPairwiseId, authCode);
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(FAILED_TO_GET_ACCESS_TOKEN_FROM_DYNAMO_ERROR, e);
        }

        if (orchAccessToken.isEmpty()) {
            LOG.info("No Orch access token found");
        }
        return orchAccessToken;
    }

    public Optional<OrchAccessTokenItem> getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
            String clientAndRpPairwiseId, String tokenValue) {
        Optional<OrchAccessTokenItem> orchAccessTokenItem =
                getAccessTokensForClientAndRpPairwiseId(clientAndRpPairwiseId).stream()
                        .filter(item -> Objects.equals(item.getToken(), tokenValue))
                        .findFirst();

        Optional<OrchAccessTokenItem> orchAccessTokenItemFromNewTable =
                getAccessTokensForClientAndRpPairwiseIdFromNewTable(clientAndRpPairwiseId).stream()
                        .filter(item -> Objects.equals(item.getToken(), tokenValue))
                        .findFirst();

        if (orchAccessTokenItem.isEmpty()) {
            LOG.info("No Orch access token found");
            if (!orchAccessTokenItemFromNewTable.isEmpty()) {
                LOG.warn("Access token was found in the new table but not in the old table");
            }
        } else {
            if (orchAccessTokenItemFromNewTable.isEmpty()) {
                LOG.warn("Access token was found in the old table but not in the new table");
            } else {
                if (!orchAccessTokenItem.get().equals(orchAccessTokenItemFromNewTable.get())) {
                    LOG.warn("Access token from new table does not match the old table");
                } else {
                    LOG.info("Access tokens match");
                }
            }
        }
        return orchAccessTokenItem;
    }

    public Optional<OrchAccessTokenItem> getAccessTokenForAuthCode(String authCode) {
        try {
            var items = oldOrchAccessTokenService.queryIndex(AUTH_CODE_INDEX, authCode);
            if (items.isEmpty()) {
                LOG.info("No Orch access token found");
                return Optional.empty();
            }
            return Optional.of(items.get(0));
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(FAILED_TO_GET_ACCESS_TOKEN_FROM_DYNAMO_ERROR, e);
            return Optional.empty();
        }
    }

    private List<OrchAccessTokenItem> getAccessTokensForClientAndRpPairwiseId(
            String clientAndRpPairwiseId) {
        List<OrchAccessTokenItem> orchAccessTokens = List.of();
        try {
            orchAccessTokens =
                    oldOrchAccessTokenService.queryTableStream(clientAndRpPairwiseId).toList();
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(FAILED_TO_GET_ACCESS_TOKEN_FROM_DYNAMO_ERROR, e);
        }
        if (orchAccessTokens.isEmpty()) {
            LOG.info("No Orch access token found");
        }
        return orchAccessTokens;
    }

    private List<OrchAccessTokenItem> getAccessTokensForClientAndRpPairwiseIdFromNewTable(
            String clientAndRpPairwiseId) {
        List<OrchAccessTokenItem> orchAccessTokens = List.of();
        try {
            orchAccessTokens =
                    newOrchAccessTokenService.queryTableStream(clientAndRpPairwiseId).toList();
        } catch (Exception e) {
            LOG.warn("Failed to get access token from new table. Error: {}", e.getMessage());
        }
        if (orchAccessTokens.isEmpty()) {
            LOG.warn("No Orch access token found in new table");
        }
        return orchAccessTokens;
    }

    public void saveAccessToken(
            String clientAndRpPairwiseId,
            String authCode,
            String token,
            String internalPairwiseSubjectId,
            String clientSessionId) {
        var itemTtl = nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS).toInstant().getEpochSecond();
        OrchAccessTokenItem orchAccessTokenItem =
                new OrchAccessTokenItem()
                        .withClientAndRpPairwiseId(clientAndRpPairwiseId)
                        .withToken(token)
                        .withInternalPairwiseSubjectId(internalPairwiseSubjectId)
                        .withClientSessionId(clientSessionId)
                        .withAuthCode(authCode)
                        .withTimeToLive(itemTtl);
        try {
            oldOrchAccessTokenService.put(orchAccessTokenItem);
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(
                    "Failed to save Orch access token item to Dynamo", e);
        }
        try {
            newOrchAccessTokenService.put(orchAccessTokenItem);
        } catch (Exception e) {
            LOG.warn("Failed to save to new OrchAccessToken table");
        }
    }

    private void logAndThrowOrchAccessTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchAccessTokenException(message);
    }
}
