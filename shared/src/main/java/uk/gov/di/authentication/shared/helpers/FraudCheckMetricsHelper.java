package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;

public class FraudCheckMetricsHelper {
    private FraudCheckMetricsHelper() {}

    private static final List<NotificationType> notificationSetupTypes =
            List.of(NotificationType.VERIFY_EMAIL, NotificationType.VERIFY_PHONE_NUMBER);

    public static void incrementUserSubmittedCredentialIfNotificationSetupJourney(
            CloudwatchMetricsService metricsService,
            JourneyType journeyType,
            NotificationType notificationType,
            String environment) {
        if (notificationSetupTypes.contains(notificationType)) {
            var credentialType = notificationType.isEmail() ? "EMAIL_ADDRESS" : "PHONE_NUMBER";
            metricsService.incrementCounter(
                    "UserSubmittedCredential",
                    Map.ofEntries(
                            Map.entry(ENVIRONMENT.getValue(), environment),
                            Map.entry("JourneyType", journeyType.getValue()),
                            Map.entry("CredentialType", credentialType)));
        }
    }
}
