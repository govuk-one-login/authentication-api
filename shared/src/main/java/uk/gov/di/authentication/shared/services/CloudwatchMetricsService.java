package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.Map;

import static java.lang.String.valueOf;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ACCOUNT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.CLIENT_NAME;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.IPV_RESPONSE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.IS_TEST;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.MFA_REQUIRED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.REQUESTED_LEVEL_OF_CONFIDENCE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AUTHENTICATION_SUCCESS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AUTHENTICATION_SUCCESS_EXISTING_ACCOUNT_BY_CLIENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AUTHENTICATION_SUCCESS_NEW_ACCOUNT_BY_CLIENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.EMAIL_CHECK_DURATION;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.MFA_RESET_AUTHORISATION_ERROR;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.MFA_RESET_HANDOFF;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.MFA_RESET_IPV_RESPONSE;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class CloudwatchMetricsService {

    private static final Logger LOG = LogManager.getLogger(CloudwatchMetricsService.class);

    private final ConfigurationService configurationService;

    public CloudwatchMetricsService() {
        configurationService = ConfigurationService.getInstance();
    }

    public CloudwatchMetricsService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public void putEmbeddedValue(String name, double value, Map<String, String> dimensions) {
        segmentedFunctionCall(
                "Metrics::EMF", () -> emitMetric(name, value, dimensions, new MetricsLogger()));
    }

    protected void emitMetric(
            String name, double value, Map<String, String> dimensions, MetricsLogger metrics) {
        try {
            var dimensionsSet = new DimensionSet();

            dimensions.forEach(dimensionsSet::addDimension);

            metrics.setNamespace("Authentication");
            metrics.putDimensions(dimensionsSet);
            metrics.putMetric(name, value, Unit.NONE);
            metrics.flush();
        } catch (IllegalArgumentException e) {
            LOG.error("Error emitting metric: {} ({})", e.getMessage(), e.getClass());
        }
    }

    public void incrementCounter(String name, Map<String, String> dimensions) {
        putEmbeddedValue(name, 1, dimensions);
    }

    public void incrementMfaMethodCounter(
            String environment,
            String operation,
            String result,
            JourneyType journeyType,
            String mfaMethodType,
            PriorityIdentifier priorityIdentifier) {
        incrementCounter(
                "MfaMethodOperationCount",
                Map.of(
                        "Environment",
                        environment,
                        "Operation",
                        operation,
                        "Result",
                        result,
                        "JourneyType",
                        valueOf(journeyType),
                        "MfaMethodType",
                        valueOf(mfaMethodType),
                        "PriorityIdentifier",
                        valueOf(priorityIdentifier)));
    }

    public void incrementAuthenticationSuccess(
            AuthSessionItem.AccountState accountState,
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
        if (AuthSessionItem.AccountState.NEW.equals(accountState) && !isTestJourney) {
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
        if (AuthSessionItem.AccountState.EXISTING.equals(accountState) && !isTestJourney) {
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

    public void incrementMfaResetHandoffCount() {
        incrementCounter(
                MFA_RESET_HANDOFF.getValue(),
                Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }

    public void incrementMfaResetIpvResponseCount(String ipvResponse) {
        incrementCounter(
                MFA_RESET_IPV_RESPONSE.getValue(),
                Map.of(
                        ENVIRONMENT.getValue(),
                        configurationService.getEnvironment(),
                        IPV_RESPONSE.getValue(),
                        ipvResponse));
    }

    public void incrementReverifyAuthorisationErrorCount() {
        incrementCounter(
                MFA_RESET_AUTHORISATION_ERROR.getValue(),
                Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }

    public DimensionSet getDimensions(Map<String, String> dimensions) {
        DimensionSet dimensionSet = new DimensionSet();

        dimensionSet.addDimension("Environment", configurationService.getEnvironment());
        dimensions.forEach(dimensionSet::addDimension);

        return dimensionSet;
    }
}
