package uk.gov.di.authentication.oidc.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.services.ClientRateLimitDataService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_NAME;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.TEST_CLIENT_ID;

class SlidingWindowAlgorithmTest {
    private final ClientRateLimitDataService rateLimitDataService =
            mock(ClientRateLimitDataService.class);
    private final CloudwatchMetricsService metrics = mock(CloudwatchMetricsService.class);
    private static final LocalDateTime CURRENT_PERIOD = LocalDateTime.parse("2025-07-15T16:27");
    private static final LocalDateTime PREVIOUS_PERIOD = CURRENT_PERIOD.minusMinutes(1);
    private SlidingWindowAlgorithm slidingWindowAlgorithm;

    @Test
    void shouldNotRateLimitIfClientHasNoRateLimitData() {
        var clientConfig = clientWithRateLimit(10);

        fixCurrentTime(CURRENT_PERIOD.plusSeconds(30));
        var rateLimitExceeded = slidingWindowAlgorithm.hasRateLimitExceeded(clientConfig);

        assertFalse(rateLimitExceeded);
    }

    @Test
    void shouldNotRateLimitIfClientDoesNotHaveRequestCountThatExceedsLimitInCurrentPeriod() {
        var clientConfig = clientWithRateLimit(10);
        setupRateLimitDataAt(CURRENT_PERIOD, 9L);

        fixCurrentTime(CURRENT_PERIOD.plusSeconds(30));
        var rateLimitExceeded = slidingWindowAlgorithm.hasRateLimitExceeded(clientConfig);

        assertFalse(rateLimitExceeded);
    }

    @Test
    void shouldRateLimitIfClientHasRequestCountThatExceedsLimitInCurrentPeriod() {
        var clientConfig = clientWithRateLimit(10);
        setupRateLimitDataAt(CURRENT_PERIOD, 11L);

        fixCurrentTime(CURRENT_PERIOD.plusSeconds(30));
        var rateLimitExceeded = slidingWindowAlgorithm.hasRateLimitExceeded(clientConfig);

        assertTrue(rateLimitExceeded);
    }

    @Test
    void shouldRateLimitIfClientHasRequestCountThatExceedsLimitAcrossTwoPeriods() {
        var clientConfig = clientWithRateLimit(10);
        setupRateLimitDataAt(PREVIOUS_PERIOD, 10L);
        setupRateLimitDataAt(CURRENT_PERIOD, 6L);

        fixCurrentTime(CURRENT_PERIOD.plusSeconds(30));
        var rateLimitExceeded = slidingWindowAlgorithm.hasRateLimitExceeded(clientConfig);

        assertTrue(rateLimitExceeded);
    }

    @Test
    void shouldNotRateLimitIfClientDoesNotHaveRequestCountThatExceedsLimitAcrossTwoPeriods() {
        var clientConfig = clientWithRateLimit(10);
        setupRateLimitDataAt(PREVIOUS_PERIOD, 10L);
        setupRateLimitDataAt(CURRENT_PERIOD, 4L);

        fixCurrentTime(CURRENT_PERIOD.plusSeconds(30));
        var rateLimitExceeded = slidingWindowAlgorithm.hasRateLimitExceeded(clientConfig);

        assertFalse(rateLimitExceeded);
    }

    private static ClientRateLimitConfig clientWithRateLimit(Integer rateLimit) {
        return new ClientRateLimitConfig(TEST_CLIENT_ID, CLIENT_NAME, rateLimit);
    }

    private void setupRateLimitDataAt(LocalDateTime period, long requestCount) {
        when(rateLimitDataService.getData(TEST_CLIENT_ID, period))
                .thenReturn(
                        Optional.of(
                                new SlidingWindowData(TEST_CLIENT_ID, period)
                                        .withRequestCount(requestCount)));
    }

    private void fixCurrentTime(LocalDateTime time) {
        slidingWindowAlgorithm =
                new SlidingWindowAlgorithm(
                        rateLimitDataService,
                        Clock.fixed(time.toInstant(ZoneOffset.UTC), ZoneOffset.UTC),
                        metrics);
    }
}
