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
}
