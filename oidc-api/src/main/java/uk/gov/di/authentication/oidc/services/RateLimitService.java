package uk.gov.di.authentication.oidc.services;

import uk.gov.di.authentication.oidc.entity.ClientRateLimitConfig;
import uk.gov.di.authentication.oidc.entity.RateLimitAlgorithm;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;

public class RateLimitService {

    private final RateLimitAlgorithm rateLimitAlgorithm;

    public RateLimitService(RateLimitAlgorithm rateLimitAlgorithm) {
        this.rateLimitAlgorithm = rateLimitAlgorithm;
    }

    public RateLimitDecision getClientRateLimitDecision(
            ClientRateLimitConfig clientRateLimitConfig) {
        if (clientRateLimitConfig.rateLimit() == null) {
            return RateLimitDecision.UNDER_LIMIT_NO_ACTION;
        }

        return rateLimitAlgorithm.getClientRateLimitDecision(clientRateLimitConfig);
    }
}
