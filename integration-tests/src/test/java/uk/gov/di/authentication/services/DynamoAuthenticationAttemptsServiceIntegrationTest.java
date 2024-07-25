package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationAttemptsService;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoAuthenticationAttemptsServiceIntegrationTest {

    private static final String ATTEMPT_IDENTIFIER = "attempt-identifier-1234";
    private static final String NON_EXISTENT_ATTEMPT_IDENTIFIER =
            "non-existent-attempt-identifier-1234";

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    DynamoAuthenticationAttemptsService dynamoAuthenticationAttemptsService =
            new DynamoAuthenticationAttemptsService(ConfigurationService.getInstance());

    @Test
    void shouldAddCode() {
        long mockedTimestamp = 1721979370L;
        long ttlInSeconds = 60L;
        long expectedTTL = mockedTimestamp + ttlInSeconds;

        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(mockedTimestamp)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(ttlInSeconds, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(expectedTTL)));

            dynamoAuthenticationAttemptsService.addCode(ATTEMPT_IDENTIFIER, ttlInSeconds);

            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                            ATTEMPT_IDENTIFIER);

            assertTrue(authenticationAttempts.isPresent());
            assertEquals(expectedTTL, authenticationAttempts.get().getTimeToLive());
        }
    }

    @Test
    void shouldGetIncorrectReauthEmailCountForUser() {
        var ttl = Instant.now().getEpochSecond() + 60L;

        // Setup the count
        dynamoAuthenticationAttemptsService.createOrIncrementCount(ATTEMPT_IDENTIFIER, ttl);

        // Retrieve the count
        var incorrectEmailCount =
                dynamoAuthenticationAttemptsService
                        .getAuthenticationAttempts(ATTEMPT_IDENTIFIER)
                        .get()
                        .getCount();

        assertEquals(1, incorrectEmailCount);
    }

    @Test
    void shouldNotRetrieveANonExistentCount() {
        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                        NON_EXISTENT_ATTEMPT_IDENTIFIER);

        assertTrue(count.isEmpty());
    }

    @Test
    void shouldNotRetrieveACountWithAnExpiredTTL() {
        long expiredTTL = Instant.now().getEpochSecond() - 1L;

        // Setup the count with an expired TTL
        dynamoAuthenticationAttemptsService.createOrIncrementCount(ATTEMPT_IDENTIFIER, expiredTTL);

        // Attempt to retrieve the count
        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);

        assertTrue(count.isEmpty(), "Expired attempt should not be retrieved");
    }

    @Test
    void shouldIncrementExistingCountWhenAuthenticationAttemptFails() {
        var nonExpiredTTL = Instant.now().getEpochSecond() + 1000000L;

        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                ATTEMPT_IDENTIFIER, nonExpiredTTL);
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                ATTEMPT_IDENTIFIER, nonExpiredTTL);

        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);
        assertEquals(2, count.get().getCount());
    }
}
