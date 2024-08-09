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

    private static final String INTERNAL_SUBJECT_ID = "internal-sub-id";

    private static final String JOURNEY_TYPE = "journey-type";
    private static final String NON_EXISTENT_INTERNAL_SUBJECT_ID = "non-existent-internal-sub-id";
    private static final String CODE = "123456";
    private static final long MOCKEDTIMESTAMP = 1721979370L;
    private static final long TTLINSECONDS = 60L;
    private static final String AUTH_METHOD = "SMS";
    private static final long EXPECTEDTTL = MOCKEDTIMESTAMP + TTLINSECONDS;

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    DynamoAuthenticationAttemptsService dynamoAuthenticationAttemptsService =
            new DynamoAuthenticationAttemptsService(ConfigurationService.getInstance());

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
                    INTERNAL_SUBJECT_ID, TTLINSECONDS, CODE, AUTH_METHOD, JOURNEY_TYPE);

            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                            INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);

            assertTrue(authenticationAttempts.isPresent());
            assertEquals(EXPECTEDTTL, authenticationAttempts.get().getTimeToLive());
        }
    }

    @Test
    void shouldGetIncorrectReauthEmailCountForUser() {
        var ttl = Instant.now().getEpochSecond() + 60L;

        // Setup the count
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, ttl, AUTH_METHOD, JOURNEY_TYPE);

        // Retrieve the count
        var incorrectEmailCount =
                dynamoAuthenticationAttemptsService
                        .getAuthenticationAttempt(INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE)
                        .get()
                        .getCount();

        assertEquals(1, incorrectEmailCount);
    }

    @Test
    void shouldNotRetrieveANonExistentCount() {
        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                        NON_EXISTENT_INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);

        assertTrue(count.isEmpty());
    }

    @Test
    void shouldNotRetrieveACountWithAnExpiredTTL() {
        long expiredTTL = Instant.now().getEpochSecond() - 1L;

        // Setup the count with an expired TTL
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, expiredTTL, AUTH_METHOD, JOURNEY_TYPE);

        // Attempt to retrieve the count
        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                        INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);

        assertTrue(count.isEmpty(), "Expired attempt should not be retrieved");
    }

    @Test
    void shouldIncrementExistingCountWhenAuthenticationAttemptFails() {
        var nonExpiredTTL = Instant.now().getEpochSecond() + 1000000L;

        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, nonExpiredTTL, AUTH_METHOD, JOURNEY_TYPE);
        dynamoAuthenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, nonExpiredTTL, AUTH_METHOD, JOURNEY_TYPE);

        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                        INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);
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
                    INTERNAL_SUBJECT_ID, TTLINSECONDS, CODE, AUTH_METHOD, JOURNEY_TYPE);

            // Read the code
            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                            INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);
            assertTrue(authenticationAttempts.isPresent());
            assertEquals(CODE, authenticationAttempts.get().getCode());

            // Delete the code
            dynamoAuthenticationAttemptsService.deleteCode(
                    INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);
            var deletedAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                            INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);
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
                    INTERNAL_SUBJECT_ID, EXPECTEDTTL, AUTH_METHOD, JOURNEY_TYPE);

            // Read the count
            var authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                            INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);
            assertTrue(authenticationAttempts.isPresent());
            assertEquals(1, authenticationAttempts.get().getCount());

            // Delete the count
            dynamoAuthenticationAttemptsService.deleteCount(
                    INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);

            // Verify the count is deleted
            authenticationAttempts =
                    dynamoAuthenticationAttemptsService.getAuthenticationAttempt(
                            INTERNAL_SUBJECT_ID, AUTH_METHOD, JOURNEY_TYPE);
            assertTrue(authenticationAttempts.isPresent());
            assertEquals(0, authenticationAttempts.get().getCount());
        }
    }
}
