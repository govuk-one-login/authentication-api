package uk.gov.di.authentication.shared.services;

import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Map;

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
            String requestedLevelOfConfidence,
            boolean isTestJourney,
            boolean mfaRequired) {
        incrementCounter(
                "AuthenticationSuccess",
                Map.of(
                        "Account",
                        accountState.name(),
                        "Environment",
                        configurationService.getEnvironment(),
                        "Client",
                        clientId,
                        "IsTest",
                        Boolean.toString(isTestJourney),
                        "RequestedLevelOfConfidence",
                        requestedLevelOfConfidence,
                        "MfaRequired",
                        Boolean.toString(mfaRequired)));
    }
}
