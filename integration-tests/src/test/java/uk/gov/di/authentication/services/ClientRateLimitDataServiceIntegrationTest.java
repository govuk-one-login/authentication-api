package uk.gov.di.authentication.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.oidc.entity.SlidingWindowData;
import uk.gov.di.orchestration.sharedtest.extensions.ClientRateLimitExtension;

import java.time.Clock;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.TEST_CLIENT_ID;

class ClientRateLimitDataServiceIntegrationTest {
    private static final LocalDateTime TEST_PERIOD_START_TIME =
            LocalDateTime.parse("2025-09-14T11:50:00");

    @RegisterExtension
    protected static final ClientRateLimitExtension clientRateLimitExtension =
            new ClientRateLimitExtension();

    @BeforeEach
    void setup() {
        clientRateLimitExtension.setClock(Clock.systemUTC());
    }

    @Test
    void shouldStoreAndRetrieveRateLimitData() {
        var expectedRateLimitData =
                new SlidingWindowData()
                        .withClientId(TEST_CLIENT_ID)
                        .withPeriodStartTime(TEST_PERIOD_START_TIME)
                        .withRequestCount(123L);
        clientRateLimitExtension.storeData(expectedRateLimitData);

        var actualRateLimitData =
                clientRateLimitExtension
                        .getData(TEST_CLIENT_ID, TEST_PERIOD_START_TIME)
                        .orElseThrow();
        assertEquals(TEST_CLIENT_ID, actualRateLimitData.getClientId());
        assertEquals(TEST_PERIOD_START_TIME, actualRateLimitData.getPeriodStartTime());
        assertEquals(123L, actualRateLimitData.getRequestCount());
    }
}
