package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem.AccountState;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ACCOUNT_INTERVENTION_STATE;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT_NAME;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.LOGOUT_SUCCESS;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.SIGN_IN_NEW_ACCOUNT_BY_CLIENT;

public class Metrics {

    private static final Logger LOG = LogManager.getLogger(Metrics.class);

    private final ConfigurationService configurationService;

    public Metrics() {
        configurationService = ConfigurationService.getInstance();
    }

    public Metrics(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public void emit(String name, double value, Map<String, String> dimensions) {
        try {
            var metrics = new MetricsLogger();
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

    public void increment(String name, Map<String, String> dimensions) {
        emit(name, 1, dimensions);
    }

    public void incrementSignInByClient(
            AccountState accountState, String clientId, String clientName) {

        var metric =
                switch (accountState) {
                    case NEW -> SIGN_IN_NEW_ACCOUNT_BY_CLIENT;
                    case EXISTING -> SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT;
                    default -> null;
                };

        if (metric != null) {
            increment(
                    metric.getValue(),
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
        increment(
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
