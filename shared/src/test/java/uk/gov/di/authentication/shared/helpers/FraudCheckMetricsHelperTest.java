package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.FraudCheckMetricsHelper.incrementUserSubmittedCredentialIfNotificationSetupJourney;

class FraudCheckMetricsHelperTest {

    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private static Stream<Arguments> setupNotificationTypesToExpectedCredentialTypes() {
        return Stream.of(
                Arguments.of(VERIFY_EMAIL, "EMAIL_ADDRESS"),
                Arguments.of(VERIFY_PHONE_NUMBER, "PHONE_NUMBER"));
    }

    @ParameterizedTest
    @MethodSource("setupNotificationTypesToExpectedCredentialTypes")
    void shouldIncrementMetricIfNotificationTypeIsVerifyPhoneNumberOrVerifyEmail(
            NotificationType notificationType, String expectedCredentialType) {
        var journeyType = JourneyType.REGISTRATION;
        var environment = "test-env";
        incrementUserSubmittedCredentialIfNotificationSetupJourney(
                cloudwatchMetricsService, journeyType, notificationType, environment);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "UserSubmittedCredential",
                        Map.ofEntries(
                                Map.entry("Environment", environment),
                                Map.entry("JourneyType", journeyType.getValue()),
                                Map.entry("CredentialType", expectedCredentialType)));
    }

    private static Stream<NotificationType> nonSetupNotificationTypes() {
        var setupNotificationTypes = List.of(VERIFY_EMAIL, VERIFY_PHONE_NUMBER);
        return Arrays.stream(NotificationType.values())
                .filter(notificationType -> !setupNotificationTypes.contains(notificationType));
    }

    @ParameterizedTest
    @MethodSource("nonSetupNotificationTypes")
    void shouldNotIncrementMetricIfAnyOtherNotificationType(NotificationType notificationType) {
        incrementUserSubmittedCredentialIfNotificationSetupJourney(
                cloudwatchMetricsService, JourneyType.SIGN_IN, notificationType, "test-env");

        verify(cloudwatchMetricsService, never()).incrementCounter(any(), anyMap());
    }
}
