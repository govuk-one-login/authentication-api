package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.ClientRateLimitConfig;
import uk.gov.di.authentication.oidc.entity.RateLimitAlgorithm;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;

import java.util.Map;

public class RateLimitService {

    private final RateLimitAlgorithm rateLimitAlgorithm;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private static final Logger LOG = LogManager.getLogger(RateLimitService.class);

    public RateLimitService(
            RateLimitAlgorithm rateLimitAlgorithm,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.rateLimitAlgorithm = rateLimitAlgorithm;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public RateLimitDecision getClientRateLimitDecision(
            ClientRateLimitConfig clientRateLimitConfig) {
        if (clientRateLimitConfig.rateLimit() == null) {
            return RateLimitDecision.NOT_CONFIGURED_NO_ACTION;
        }

        var rateLimitExceeded = rateLimitAlgorithm.hasRateLimitExceeded(clientRateLimitConfig);

        if (rateLimitExceeded) {
            var decision = RateLimitDecision.OVER_LIMIT_RETURN_TO_RP;
            emitRateLimitExceededMetric(decision, clientRateLimitConfig.clientID());

            return decision;
        }
        return RateLimitDecision.UNDER_LIMIT_NO_ACTION;
    }

    private void emitRateLimitExceededMetric(RateLimitDecision rateLimitDecision, String clientId) {
        try {
            cloudwatchMetricsService.incrementCounter(
                    "RpRateLimitExceeded",
                    Map.of(
                            "clientId",
                            clientId,
                            "action",
                            rateLimitDecision.getAction().toString()));
        } catch (Exception e) {
            LOG.warn("Error incrementing RpRateLimitExceeded metric", e);
        }
    }
}
