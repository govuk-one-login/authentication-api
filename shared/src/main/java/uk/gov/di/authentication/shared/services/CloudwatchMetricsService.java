package uk.gov.di.authentication.shared.services;

import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ACCOUNT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.CLIENT_NAME;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.IS_TEST;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.MFA_REQUIRED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.REQUESTED_LEVEL_OF_CONFIDENCE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AUTHENTICATION_SUCCESS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AUTHENTICATION_SUCCESS_EXISTING_ACCOUNT_BY_CLIENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AUTHENTICATION_SUCCESS_NEW_ACCOUNT_BY_CLIENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.EMAIL_CHECK_DURATION;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.NEW;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class CloudwatchMetricsService {

    private final ConfigurationService configurationService;

    public CloudwatchMetricsService() {
        configurationService = ConfigurationService.getInstance();
    }

    public CloudwatchMetricsService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public void putEmbeddedValue(String name, double value, Map<String, String> dimensions) {
        segmentedFunctionCall(
                "Metrics::EMF",
                () -> {
                    var metrics = new MetricsLogger();
                    var dimensionsSet = new DimensionSet();

                    dimensions.forEach(dimensionsSet::addDimension);

                    metrics.setNamespace("Authentication");
                    metrics.putDimensions(dimensionsSet);
                    metrics.putMetric(name, value, Unit.NONE);
                    metrics.flush();
                });
    }

    public void incrementCounter(String name, Map<String, String> dimensions) {
        putEmbeddedValue(name, 1, dimensions);
    }

    public void incrementAuthenticationSuccess(
            Session.AccountState accountState,
            String clientId,
            String clientName,
            String requestedLevelOfConfidence,
            boolean isTestJourney,
            boolean mfaRequired) {
        incrementCounter(
                AUTHENTICATION_SUCCESS.getValue(),
                Map.of(
                        ACCOUNT.getValue(),
                        accountState.name(),
                        ENVIRONMENT.getValue(),
                        configurationService.getEnvironment(),
                        CLIENT.getValue(),
                        clientId,
                        IS_TEST.getValue(),
                        Boolean.toString(isTestJourney),
                        REQUESTED_LEVEL_OF_CONFIDENCE.getValue(),
                        requestedLevelOfConfidence,
                        MFA_REQUIRED.getValue(),
                        Boolean.toString(mfaRequired),
                        CLIENT_NAME.getValue(),
                        clientName));
        if (NEW.equals(accountState) && !isTestJourney) {
            incrementCounter(
                    AUTHENTICATION_SUCCESS_NEW_ACCOUNT_BY_CLIENT.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            CLIENT.getValue(),
                            clientId,
                            CLIENT_NAME.getValue(),
                            clientName));
        }
        if (EXISTING.equals(accountState) && !isTestJourney) {
            incrementCounter(
                    AUTHENTICATION_SUCCESS_EXISTING_ACCOUNT_BY_CLIENT.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            CLIENT.getValue(),
                            clientId,
                            CLIENT_NAME.getValue(),
                            clientName));
        }
    }

    public void logEmailCheckDuration(long duration) {
        this.putEmbeddedValue(
                EMAIL_CHECK_DURATION.getValue(),
                duration,
                Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }
}
