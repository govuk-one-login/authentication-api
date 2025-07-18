package uk.gov.di.authentication.oidc.entity;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.services.ClientRateLimitDataService;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class SlidingWindowAlgorithm implements RateLimitAlgorithm {
    private static final Logger LOG = LogManager.getLogger(SlidingWindowAlgorithm.class);
    private static final int PERIOD_LENGTH_IN_SECONDS = 60;
    private final ClientRateLimitDataService rateLimitDataService;
    private final NowHelper.NowClock nowClock;

    public SlidingWindowAlgorithm(ConfigurationService configurationService) {
        this(new ClientRateLimitDataService(configurationService));
    }

    public SlidingWindowAlgorithm(ClientRateLimitDataService clientRateLimitDataService) {
        this(clientRateLimitDataService, Clock.systemUTC());
    }

    public SlidingWindowAlgorithm(
            ClientRateLimitDataService clientRateLimitDataService, Clock clock) {
        this.rateLimitDataService = clientRateLimitDataService;
        this.nowClock = new NowHelper.NowClock(clock);
    }

    @Override
    public boolean hasRateLimitExceeded(ClientRateLimitConfig rateLimitConfig) {
        var clientId = rateLimitConfig.clientID();
        var rateLimit = rateLimitConfig.rateLimit();

        var currentTimestamp = nowClock.now().toInstant().atZone(ZoneOffset.UTC).toLocalDateTime();
        var currentPeriod = getTimeToMinPrecision(currentTimestamp);
        var previousTimestamp = currentTimestamp.minusSeconds(PERIOD_LENGTH_IN_SECONDS);
        var previousPeriod = getTimeToMinPrecision(previousTimestamp);

        long currentCount =
                rateLimitDataService
                        .getData(clientId, currentPeriod)
                        .map(SlidingWindowData::getRequestCount)
                        .orElse(0L);
        long previousCount =
                rateLimitDataService
                        .getData(clientId, previousPeriod)
                        .map(SlidingWindowData::getRequestCount)
                        .orElse(0L);

        // Calculate how many seconds into the current period we are in
        var secondsFromCurrentPeriodInWindow =
                currentTimestamp.toEpochSecond(ZoneOffset.UTC)
                        - currentPeriod.toEpochSecond(ZoneOffset.UTC);

        // Calculate how many seconds from the previous period should be included in this window
        // e.g 20 seconds into current period means the rest of the 60-second window sits in the
        // last 40 seconds of the previous period
        // Note that the window has the same length as the period (60 seconds)
        var secondsFromPreviousPeriodInWindow =
                PERIOD_LENGTH_IN_SECONDS - secondsFromCurrentPeriodInWindow;

        // Scale previous period count by the ratio of seconds from the previous period that are in
        // the current window, to seconds in the current window
        // e.g If previous period has 10 requests, and the window is 30 seconds (halfway) into the
        // current period, then we would scale 10 by 1/2 (30/60), to give us 5 requests
        var previousCountInWindow =
                previousCount
                        * ((double) secondsFromPreviousPeriodInWindow / PERIOD_LENGTH_IN_SECONDS);
        if (previousCountInWindow + currentCount > rateLimit) {
            LOG.warn(
                    "Client with ID {} has exceeded rate limit. Current count: {}. Limit {}",
                    rateLimitConfig.clientID(),
                    (int) previousCountInWindow + currentCount,
                    rateLimit);
            return true;
        }
        // TODO: Increment count if not over limit yet (ATO-1816)
        return false;
    }

    private static LocalDateTime getTimeToMinPrecision(LocalDateTime fullTime) {
        return fullTime.withSecond(0).withNano(0);
    }
}
