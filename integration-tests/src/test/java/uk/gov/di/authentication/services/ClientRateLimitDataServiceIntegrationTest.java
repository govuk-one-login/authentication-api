package uk.gov.di.authentication.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.sharedtest.extensions.ClientRateLimitExtension;

import java.time.Clock;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.TEST_CLIENT_ID;

class ClientRateLimitDataServiceIntegrationTest {
    private static final LocalDateTime TEST_PERIOD_START_TIME =
            LocalDateTime.parse("2025-09-14T11:50:00");

    @RegisterExtension
    protected static final ClientRateLimitExtension rateLimitDataExtension =
            new ClientRateLimitExtension();

    @BeforeEach
    void setup() {
        rateLimitDataExtension.setClock(Clock.systemUTC());
    }

    @Nested
    class SlidingWindowAlgorithm {
        @Test
        void shouldCreateRateLimitDataWhenIncrementingIfNoDataExisted() {
            rateLimitDataExtension.increment(TEST_CLIENT_ID, TEST_PERIOD_START_TIME);

            var actualRateLimitData =
                    rateLimitDataExtension
                            .getData(TEST_CLIENT_ID, TEST_PERIOD_START_TIME)
                            .orElseThrow();
            assertEquals(1L, actualRateLimitData.getRequestCount());
        }

        @Test
        void shouldUpdateRateLimitDataWhenIncrementingIfDataExists() {
            rateLimitDataExtension.increment(TEST_CLIENT_ID, TEST_PERIOD_START_TIME);
            rateLimitDataExtension.increment(TEST_CLIENT_ID, TEST_PERIOD_START_TIME);

            var actualRateLimitData =
                    rateLimitDataExtension
                            .getData(TEST_CLIENT_ID, TEST_PERIOD_START_TIME)
                            .orElseThrow();
            assertEquals(2L, actualRateLimitData.getRequestCount());
        }
    }
}
