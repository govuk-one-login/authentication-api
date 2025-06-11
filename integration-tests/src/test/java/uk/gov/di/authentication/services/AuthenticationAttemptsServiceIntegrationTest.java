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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthenticationAttemptsServiceIntegrationTest {

    private static final String INTERNAL_SUBJECT_ID = "internal-sub-id";
    private static final String RP_PAIRWISE_ID = "RP_PAIRWISE_ID";

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

    // TODO remove temporary ZDD measure to sum deprecated count types
    @Test
    void shouldIncludeDeprecatedMfaCountsWhenFetching() {
        var ttl = Instant.now().getEpochSecond() + 60L;

        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, ttl, JOURNEY_TYPE, CountType.ENTER_SMS_CODE);
        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, ttl, JOURNEY_TYPE, CountType.ENTER_AUTH_APP_CODE);
        authenticationAttemptsService.createOrIncrementCount(
                INTERNAL_SUBJECT_ID, ttl, JOURNEY_TYPE, CountType.ENTER_MFA_CODE);

        authenticationAttemptsService.createOrIncrementCount(
                RP_PAIRWISE_ID, ttl, JOURNEY_TYPE, CountType.ENTER_SMS_CODE);
        authenticationAttemptsService.createOrIncrementCount(
                RP_PAIRWISE_ID, ttl, JOURNEY_TYPE, CountType.ENTER_AUTH_APP_CODE);
        authenticationAttemptsService.createOrIncrementCount(
                RP_PAIRWISE_ID, ttl, JOURNEY_TYPE, CountType.ENTER_MFA_CODE);

        assertEquals(
                3,
                authenticationAttemptsService.getCount(
                        INTERNAL_SUBJECT_ID, JOURNEY_TYPE, CountType.ENTER_MFA_CODE));
        assertEquals(
                3,
                authenticationAttemptsService
                        .getCountsByJourney(INTERNAL_SUBJECT_ID, JOURNEY_TYPE)
                        .get(CountType.ENTER_MFA_CODE));
        assertEquals(
                6,
                authenticationAttemptsService
                        .getCountsByJourneyForSubjectIdAndRpPairwiseId(
                                INTERNAL_SUBJECT_ID, RP_PAIRWISE_ID, JOURNEY_TYPE)
                        .get(CountType.ENTER_MFA_CODE));
    }

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

    @Test
    void shouldGetAllCountTypesForAGivenJourney() {
        var requestedJourneyType = JourneyType.REAUTHENTICATION;
        var otherJourneyType = JourneyType.ACCOUNT_RECOVERY;
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(MOCKEDTIMESTAMP)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(TTLINSECONDS, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(EXPECTEDTTL)));

            var countTypesToCountsForRequestedJourney =
                    Map.ofEntries(
                            Map.entry(CountType.ENTER_EMAIL, 2),
                            Map.entry(CountType.ENTER_PASSWORD, 4),
                            Map.entry(CountType.ENTER_MFA_CODE, 5));

            incrementCountsForIdentifier(
                    INTERNAL_SUBJECT_ID,
                    requestedJourneyType,
                    countTypesToCountsForRequestedJourney);

            // set up some other data which should not affect the result
            authenticationAttemptsService.createOrIncrementCount(
                    INTERNAL_SUBJECT_ID, EXPECTEDTTL, otherJourneyType, CountType.ENTER_EMAIL);
            authenticationAttemptsService.createOrIncrementCount(
                    INTERNAL_SUBJECT_ID, EXPECTEDTTL, otherJourneyType, CountType.ENTER_MFA_CODE);

            // Read the count
            var authenticationAttempts =
                    authenticationAttemptsService.getCountsByJourney(
                            INTERNAL_SUBJECT_ID, JOURNEY_TYPE);
            assertEquals(countTypesToCountsForRequestedJourney, authenticationAttempts);
        }
    }

    @Test
    void shouldGetAllCountTypesForAGivenJourneyAgainstTwoIdentifiers() {
        var requestedJourneyType = JourneyType.REAUTHENTICATION;
        var otherJourneyType = JourneyType.ACCOUNT_RECOVERY;
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(MOCKEDTIMESTAMP)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(TTLINSECONDS, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(EXPECTEDTTL)));

            var countsForSubjectId =
                    Map.ofEntries(
                            Map.entry(CountType.ENTER_EMAIL, 2),
                            Map.entry(CountType.ENTER_PASSWORD, 4),
                            Map.entry(CountType.ENTER_MFA_CODE, 5));

            var countsForRpPairwiseId =
                    Map.ofEntries(
                            Map.entry(CountType.ENTER_EMAIL, 1),
                            Map.entry(CountType.ENTER_PASSWORD, 2),
                            Map.entry(CountType.ENTER_MFA_CODE, 1));

            incrementCountsForIdentifier(
                    INTERNAL_SUBJECT_ID, requestedJourneyType, countsForSubjectId);
            incrementCountsForIdentifier(
                    RP_PAIRWISE_ID, requestedJourneyType, countsForRpPairwiseId);

            // set up some other data which should not affect the result
            authenticationAttemptsService.createOrIncrementCount(
                    INTERNAL_SUBJECT_ID, EXPECTEDTTL, otherJourneyType, CountType.ENTER_EMAIL);
            authenticationAttemptsService.createOrIncrementCount(
                    INTERNAL_SUBJECT_ID, EXPECTEDTTL, otherJourneyType, CountType.ENTER_MFA_CODE);

            // Read the count
            var authenticationAttempts =
                    authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            INTERNAL_SUBJECT_ID, RP_PAIRWISE_ID, JOURNEY_TYPE);

            var expectedCountTypesAcrossBothIdentifiers =
                    Map.ofEntries(
                            Map.entry(CountType.ENTER_EMAIL, 3),
                            Map.entry(CountType.ENTER_PASSWORD, 6),
                            Map.entry(CountType.ENTER_MFA_CODE, 6));

            assertEquals(expectedCountTypesAcrossBothIdentifiers, authenticationAttempts);
        }
    }

    @Test
    void shouldCombineSmsAndAuthAppCodesIntoMfaCode() {
        var requestedJourneyType = JourneyType.REAUTHENTICATION;
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochSecond(MOCKEDTIMESTAMP)));
            mockedNowHelperClass
                    .when(() -> NowHelper.nowPlus(TTLINSECONDS, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(EXPECTEDTTL)));

            var countsForSubjectId = Map.ofEntries(Map.entry(CountType.ENTER_MFA_CODE, 3));

            var countsForRpPairwiseId = Map.ofEntries(Map.entry(CountType.ENTER_MFA_CODE, 3));

            incrementCountsForIdentifier(
                    INTERNAL_SUBJECT_ID, requestedJourneyType, countsForSubjectId);
            incrementCountsForIdentifier(
                    RP_PAIRWISE_ID, requestedJourneyType, countsForRpPairwiseId);

            var authenticationAttempts =
                    authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            INTERNAL_SUBJECT_ID, RP_PAIRWISE_ID, JOURNEY_TYPE);

            var expectedCounts = Map.ofEntries(Map.entry(CountType.ENTER_MFA_CODE, 6));

            assertEquals(expectedCounts, authenticationAttempts);
        }
    }

    private void incrementCountsForIdentifier(
            String identifier, JourneyType journeyType, Map<CountType, Integer> counts) {
        counts.entrySet()
                .forEach(
                        entry -> {
                            var countType = entry.getKey();
                            var count = entry.getValue();
                            for (int i = 0; i < count; i++) {
                                authenticationAttemptsService.createOrIncrementCount(
                                        identifier, EXPECTEDTTL, journeyType, countType);
                            }
                        });
    }
}
