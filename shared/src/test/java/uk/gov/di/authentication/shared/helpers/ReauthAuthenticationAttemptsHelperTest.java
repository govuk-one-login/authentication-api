package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReauthAuthenticationAttemptsHelperTest {
    private static final String SUBJECT_ID = new Subject().getValue();
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ReauthAuthenticationAttemptsHelper helper =
            new ReauthAuthenticationAttemptsHelper(
                    configurationService, authenticationAttemptsService);

    private static Stream<Arguments> reauthRelevantCounts() {
        return Stream.of(
                Arguments.of(CountType.ENTER_EMAIL),
                Arguments.of(CountType.ENTER_PASSWORD),
                Arguments.of(CountType.ENTER_SMS_CODE),
                Arguments.of(CountType.ENTER_AUTH_APP_CODE));
    }

    private void setupConfigurationServiceCountForCountType(
            CountType countType, int retriesAllowed) {
        switch (countType) {
            case ENTER_EMAIL -> when(configurationService.getMaxEmailReAuthRetries())
                    .thenReturn(retriesAllowed);
            case ENTER_PASSWORD -> when(configurationService.getMaxPasswordRetries())
                    .thenReturn(retriesAllowed);
            case ENTER_AUTH_APP_CODE, ENTER_SMS_CODE, ENTER_EMAIL_CODE -> when(configurationService
                            .getCodeMaxRetries())
                    .thenReturn(retriesAllowed);
        }
    }

    @ParameterizedTest
    @MethodSource("reauthRelevantCounts")
    void isBlockedForReauthReturnsTrueWhenAnyRelevantCountTypeExceedsTheThreshold(
            CountType countThatExceedsMax) {
        // Setup all counts to not exceed the max so we can isolate just the one that does exceed
        // subsequently
        Arrays.stream(CountType.values()).forEach(this::setupCountThatDoesNotExceedMax);

        var retriesAllowed = 5;
        setupConfigurationServiceCountForCountType(countThatExceedsMax, retriesAllowed);
        when(authenticationAttemptsService.getCount(
                        SUBJECT_ID, JourneyType.REAUTHENTICATION, countThatExceedsMax))
                .thenReturn(retriesAllowed + 1);

        assertTrue(helper.isBlockedForReauth(SUBJECT_ID));
    }

    @Test
    void isBlockedForReauthReturnsTrueWhenNoCountExceedsTheThreshold() {
        Arrays.stream(CountType.values()).forEach(this::setupCountThatDoesNotExceedMax);

        assertFalse(helper.isBlockedForReauth(SUBJECT_ID));
    }

    private void setupCountThatDoesNotExceedMax(CountType count) {
        var maxRetries = 4;
        when(authenticationAttemptsService.getCount(
                        SUBJECT_ID, JourneyType.REAUTHENTICATION, count))
                .thenReturn(maxRetries - 1);
        setupConfigurationServiceCountForCountType(count, maxRetries);
    }

    @Test
    void countTypesThatExceedMaxShouldReturnTheCountTypesThatHaveExceededTheirMaximums() {
        var maxEmailRetries = 5;
        var maxPasswordRetries = 6;
        var maxCodeRetries = 4;

        when(configurationService.getCodeMaxRetries()).thenReturn(maxCodeRetries);
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(maxEmailRetries);
        when(configurationService.getMaxPasswordRetries()).thenReturn(maxPasswordRetries);

        var retrievedCountTypesToCounts =
                Map.ofEntries(
                        Map.entry(CountType.ENTER_EMAIL, maxEmailRetries + 1),
                        Map.entry(CountType.ENTER_PASSWORD, maxPasswordRetries - 1),
                        Map.entry(CountType.ENTER_AUTH_APP_CODE, maxCodeRetries),
                        Map.entry(CountType.ENTER_EMAIL_CODE, 100));

        var expectedReauthCountsExceeded =
                List.of(CountType.ENTER_EMAIL, CountType.ENTER_AUTH_APP_CODE);
        var actualReauthCountsExceeded =
                helper.countTypesWhereUserIsBlockedForReauth(retrievedCountTypesToCounts);

        assertTrue(
                expectedReauthCountsExceeded.containsAll(actualReauthCountsExceeded)
                        && actualReauthCountsExceeded.containsAll(expectedReauthCountsExceeded));
    }
}
