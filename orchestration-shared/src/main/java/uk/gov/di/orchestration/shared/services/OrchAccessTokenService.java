package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.lambda.LambdaTimer;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.IntStream;

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
            LOG.info(
                    "No Orch access token found for clientAndRpPairwiseId {}",
                    clientAndRpPairwiseId);
        }
        return orchAccessToken;
    }

    public Optional<OrchAccessTokenItem> getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
            String clientAndRpPairwiseId, String tokenValue) {
        return getAccessTokensForClientAndRpPairwiseId(clientAndRpPairwiseId).stream()
                .filter(item -> Objects.equals(item.getToken(), tokenValue))
                .findFirst();
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

        List<OrchAccessTokenItem> newOrchAccessTokens = List.of();
        try {
            newOrchAccessTokens =
                    newOrchAccessTokenService.queryTableStream(clientAndRpPairwiseId).toList();
        } catch (Exception e) {
            LOG.warn(
                    "Failed to get access token from new dynamo table. Error message: {}",
                    e.getMessage());
        }

        if (orchAccessTokens.isEmpty()) {
            LOG.info(
                    "No Orch access token found for clientAndRpPairwiseId {}",
                    clientAndRpPairwiseId);
            if (!newOrchAccessTokens.isEmpty()) {
                LOG.warn("Access token(s) were found in the new table but not in the old table");
            }
        } else {
            if (newOrchAccessTokens.isEmpty()) {
                LOG.warn("Access token(s) were found in the old table but not in the new table");
            } else {
                var oldTokens = new java.util.HashSet<>(orchAccessTokens);
                var newTokens = new java.util.HashSet<>(newOrchAccessTokens);
                if (!oldTokens.equals(newTokens)) {
                    LOG.warn("Access tokens found in the tables do not match");
                }
            }
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

    public void updateAccessTokensTtlToNow(List<OrchAccessTokenItem> items) {
        try {
            var currentTtl = nowClock.now().toInstant().getEpochSecond();
            items.forEach(item -> item.setTimeToLive(currentTtl));
            oldOrchAccessTokenService.batchPut(items);
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException("Failed to batch update token TTLs", e);
        }
    }

    public void processAccessTokensWithoutTtlInBatches(
            int batchSize,
            int totalSegments,
            int maxTokens,
            LambdaTimer timer,
            Consumer<List<OrchAccessTokenItem>> batchProcessor) {

        var maxTokensReached = new AtomicBoolean(false);
        var processedCount = new AtomicInteger(0);
        try {
            IntStream.range(0, totalSegments)
                    .parallel()
                    .forEach(
                            segment -> {
                                try {
                                    // stagger start times of parallel segments
                                    Thread.sleep((long) segment * 100);
                                } catch (InterruptedException e) {
                                    // exit gracefully, allowing the other threads to complete the
                                    // batch operations
                                    Thread.currentThread().interrupt();
                                    LOG.info(
                                            "Processing interrupted for segment {}, stopping gracefully",
                                            segment);
                                    return;
                                }
                                var batch = new ArrayList<OrchAccessTokenItem>();
                                oldOrchAccessTokenService
                                        .scanTableSegment(segment, totalSegments)
                                        .filter(item -> item.getTimeToLive() == 0)
                                        .takeWhile(
                                                item ->
                                                        !maxTokensReached.get()
                                                                && timer.hasTimeRemaining(
                                                                        TIME_REMAINING_BUFFER_IN_MILLISECONDS))
                                        .forEach(
                                                item -> {
                                                    batch.add(item);
                                                    if (batch.size() == batchSize) {
                                                        batchProcessor.accept(
                                                                new ArrayList<>(batch));
                                                        if (processedCount.addAndGet(batchSize)
                                                                >= maxTokens) {
                                                            maxTokensReached.set(true);
                                                        }
                                                        batch.clear();
                                                    }
                                                });
                                if (!batch.isEmpty()) {
                                    batchProcessor.accept(batch);
                                }
                            });
        } catch (Exception e) {
            logAndThrowOrchAccessTokenException(
                    "Failed to process tokens without TTL in batches", e);
        }
    }

    private void logAndThrowOrchAccessTokenException(String message, Exception e) {
        LOG.error("{}. Error message: {}", message, e.getMessage());
        throw new OrchAccessTokenException(message);
    }
}
