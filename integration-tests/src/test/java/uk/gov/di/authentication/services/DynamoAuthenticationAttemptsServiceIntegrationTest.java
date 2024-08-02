package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationAttemptsService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoAuthenticationAttemptsServiceIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String ATTEMPT_IDENTIFIER = "attempt-identifier-1234";
    private static final String NON_EXISTENT_ATTEMPT_IDENTIFIER =
            "non-existent-attempt-identifier-1234";
    private static final String CODE = "123456";
    private static final long MOCKEDTIMESTAMP = 1721979370L;
    private static final long TTLINSECONDS = 60L;
    private static final String AUTH_METHOD = "SMS";
    private static final long EXPECTEDTTL = MOCKEDTIMESTAMP + TTLINSECONDS;

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    DynamoAuthenticationAttemptsService dynamoAuthenticationAttemptsService =
            new DynamoAuthenticationAttemptsService(TEST_CONFIGURATION_SERVICE);

    @Test
    void shouldAddCode() {

        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(MOCKEDTIMESTAMP)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(TTLINSECONDS, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(EXPECTEDTTL)));

            dynamoAuthenticationAttemptsService.addCode(
                    ATTEMPT_IDENTIFIER, TTLINSECONDS, CODE, AUTH_METHOD);

            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                            ATTEMPT_IDENTIFIER);

            assertTrue(authenticationAttempts.isPresent());
            assertEquals(EXPECTEDTTL, authenticationAttempts.get().getTimeToLive());
        }
    }

    @Test
    void shouldGetIncorrectReauthEmailCountForUser() {
        var ttl = Instant.now().getEpochSecond() + 60L;

        // Setup the count
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                ATTEMPT_IDENTIFIER, ttl, AUTH_METHOD);

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
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                ATTEMPT_IDENTIFIER, expiredTTL, AUTH_METHOD);

        // Attempt to retrieve the count
        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);

        assertTrue(count.isEmpty(), "Expired attempt should not be retrieved");
    }

    @Test
    void shouldIncrementExistingCountWhenAuthenticationAttemptFails() {
        var nonExpiredTTL = Instant.now().getEpochSecond() + 1000000L;

        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                ATTEMPT_IDENTIFIER, nonExpiredTTL, AUTH_METHOD);
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                ATTEMPT_IDENTIFIER, nonExpiredTTL, AUTH_METHOD);

        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);
        assertEquals(2, count.get().getCount());
    }

    @Test
    void shouldReadAndDeleteCodes() {

        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(MOCKEDTIMESTAMP)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(TTLINSECONDS, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(EXPECTEDTTL)));

            dynamoAuthenticationAttemptsService.addCode(
                    ATTEMPT_IDENTIFIER, TTLINSECONDS, CODE, AUTH_METHOD);

            // Read the code
            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                            ATTEMPT_IDENTIFIER);
            assertTrue(authenticationAttempts.isPresent());
            assertEquals(CODE, authenticationAttempts.get().getCode());

            // Delete the code
            dynamoAuthenticationAttemptsService.deleteCode(ATTEMPT_IDENTIFIER);
            var deletedAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                            ATTEMPT_IDENTIFIER);
            assertTrue(deletedAttempts.isEmpty() || deletedAttempts.get().getCode() == null);
        }
    }

    @Test
    void shouldReadAndDeleteCounts() {

        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(MOCKEDTIMESTAMP)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(TTLINSECONDS, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(EXPECTEDTTL)));

            // Setup the count
            dynamoAuthenticationAttemptsService.createOrIncrementCount(
                    ATTEMPT_IDENTIFIER, EXPECTEDTTL, AUTH_METHOD);

            // Read the count
            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                            ATTEMPT_IDENTIFIER);
            assertTrue(authenticationAttempts.isPresent());
            assertEquals(1, authenticationAttempts.get().getCount());

            // Delete the count
            dynamoAuthenticationAttemptsService.deleteCount(ATTEMPT_IDENTIFIER);

            // Verify the count is deleted
            authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                            ATTEMPT_IDENTIFIER);
            assertTrue(authenticationAttempts.isPresent());
            assertEquals(0, authenticationAttempts.get().getCount());
        }
    }
}
