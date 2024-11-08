package uk.gov.di.orchestration.shared.services;

import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ACCOUNT_INTERVENTION_STATE;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT_NAME;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.LOGOUT_SUCCESS;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.SIGN_IN_NEW_ACCOUNT_BY_CLIENT;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.NEW;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

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

    public void incrementSignInByClient(
            Session.AccountState accountState,
            String clientId,
            String clientName,
            boolean isTestJourney) {
        if (NEW.equals(accountState) && !isTestJourney) {
            incrementCounter(
                    SIGN_IN_NEW_ACCOUNT_BY_CLIENT.getValue(),
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
                    SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            CLIENT.getValue(),
                            clientId,
                            CLIENT_NAME.getValue(),
                            clientName));
        }
    }

    public void incrementSignInByClient(
            OrchSessionItem.AccountState accountState,
            String clientId,
            String clientName,
            boolean isTestJourney) {
        if (OrchSessionItem.AccountState.NEW.equals(accountState) && !isTestJourney) {
            incrementCounter(
                    SIGN_IN_NEW_ACCOUNT_BY_CLIENT.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            CLIENT.getValue(),
                            clientId,
                            CLIENT_NAME.getValue(),
                            clientName));
        }
        if (OrchSessionItem.AccountState.EXISTING.equals(accountState) && !isTestJourney) {
            incrementCounter(
                    SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT.getValue(),
                    Map.of(
                            ENVIRONMENT.getValue(),
                            configurationService.getEnvironment(),
                            CLIENT.getValue(),
                            clientId,
                            CLIENT_NAME.getValue(),
                            clientName));
        }
    }

    public void incrementLogout(Optional<String> clientId) {
        incrementLogout(clientId, Optional.empty());
    }

    public void incrementLogout(
            Optional<String> clientId, Optional<AccountIntervention> intervention) {
        String accountInterventionStr = "unknown";
        if (intervention.isPresent()) {
            if (intervention.get().getSuspended()) {
                accountInterventionStr = "suspended";
            }
            if (intervention.get().getBlocked()) {
                accountInterventionStr = "blocked";
            }
        }
        incrementCounter(
                LOGOUT_SUCCESS.getValue(),
                Map.of(
                        ENVIRONMENT.getValue(),
                        configurationService.getEnvironment(),
                        CLIENT.getValue(),
                        clientId.orElse("unknown"),
                        ACCOUNT_INTERVENTION_STATE.getValue(),
                        accountInterventionStr));
    }
}
