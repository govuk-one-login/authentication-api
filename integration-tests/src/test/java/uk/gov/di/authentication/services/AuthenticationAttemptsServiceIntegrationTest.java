package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthenticationAttemptsServiceIntegrationTest {

    private static final String INTERNAL_SUBJECT_ID = "internal-sub-id";

    private static final JourneyType JOURNEY_TYPE = JourneyType.REAUTHENTICATION;
    private static final String NON_EXISTENT_INTERNAL_SUBJECT_ID = "non-existent-internal-sub-id";
    private static final long MOCKEDTIMESTAMP = 1721979370L;
    private static final long TTLINSECONDS = 60L;
    private static final CountType COUNT_TYPE = CountType.ENTER_EMAIL;
    private static final long EXPECTEDTTL = MOCKEDTIMESTAMP + TTLINSECONDS;

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    AuthenticationAttemptsService authenticationAttemptsService =
            new AuthenticationAttemptsService(ConfigurationService.getInstance());

    @Test
    void shouldGetIncorrectReauthEmailCountForUser() {
        var ttl = Instant.now().getEpochSecond() + 60L;

        // Setup the count
        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, ttl, JOURNEY_TYPE, COUNT_TYPE);

        // Retrieve the count
        var incorrectEmailCount =
                authenticationAttemptsService.getCount(
                        INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);

        assertEquals(1, incorrectEmailCount);
    }

    @Test
    void shouldNotRetrieveANonExistentCount() {
        var count =
                authenticationAttemptsService.getCount(
                        NON_EXISTENT_INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);

        assertEquals(0, count);
    }

    @Test
    void shouldNotRetrieveACountWithAnExpiredTTL() {
        long expiredTTL = Instant.now().getEpochSecond() - 1L;

        // Setup the count with an expired TTL
        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, expiredTTL, JOURNEY_TYPE, COUNT_TYPE);

        // Attempt to retrieve the count
        var count =
                authenticationAttemptsService.getCount(
                        INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);

        assertEquals(0, count, "Expired attempt should not be retrieved");
    }

    @Test
    void shouldIncrementExistingCountWhenAuthenticationAttemptFails() {
        var nonExpiredTTL = Instant.now().getEpochSecond() + 1000000L;

        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, nonExpiredTTL, JOURNEY_TYPE, COUNT_TYPE);
        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, nonExpiredTTL, JOURNEY_TYPE, COUNT_TYPE);

        var count =
                authenticationAttemptsService.getCount(
                        INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);
        assertEquals(2, count);
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
            authenticationAttemptsService.createOrIncrementCount(
                    INTERNAL_SUBJECT_ID, EXPECTEDTTL, JOURNEY_TYPE, COUNT_TYPE);

            // Read the count
            var authenticationAttempts =
                    authenticationAttemptsService.getCount(
                            INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);
            assertEquals(1, authenticationAttempts);

            // Delete the count
            authenticationAttemptsService.deleteCount(
                    INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);

            // Verify the count is deleted
            authenticationAttempts =
                    authenticationAttemptsService.getCount(
                            INTERNAL_SUBJECT_ID, JOURNEY_TYPE, COUNT_TYPE);
            assertEquals(0, authenticationAttempts);
        }
    }
}
