package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.cloudwatch.CredentialType;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.CREDENTIAL_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.USER_SUBMITTED_CREDENTIAL;

public class FraudCheckMetricsHelper {
    private FraudCheckMetricsHelper() {}

    private static final List<String> notificationSetupTypes =
            List.of(
                    NotificationType.VERIFY_EMAIL.name(),
                    NotificationType.VERIFY_PHONE_NUMBER.name());

    public static void incrementUserSubmittedCredentialIfNotificationSetupJourney(
            CloudwatchMetricsService metricsService,
            JourneyType journeyType,
            String notificationType,
            String environment) {
        if (notificationSetupTypes.contains(notificationType)) {
            var credentialType =
                    Objects.equals(notificationType, NotificationType.VERIFY_EMAIL.name())
                            ? CredentialType.EMAIL_ADDRESS
                            : CredentialType.PHONE_NUMBER;
            metricsService.incrementCounter(
                    USER_SUBMITTED_CREDENTIAL.getValue(),
                    Map.ofEntries(
                            Map.entry(ENVIRONMENT.getValue(), environment),
                            Map.entry(JOURNEY_TYPE.getValue(), journeyType.getValue()),
                            Map.entry(CREDENTIAL_TYPE.getValue(), credentialType.name())));
        }
    }
}
