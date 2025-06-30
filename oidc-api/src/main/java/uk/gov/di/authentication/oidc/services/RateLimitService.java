package uk.gov.di.authentication.oidc.services;

import uk.gov.di.authentication.oidc.entity.ClientRequestInfo;
import uk.gov.di.authentication.oidc.entity.RateLimitAlgorithm;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;

public class RateLimitService {

    private final RateLimitAlgorithm rateLimitAlgorithm;

    public RateLimitService(RateLimitAlgorithm rateLimitAlgorithm) {
        this.rateLimitAlgorithm = rateLimitAlgorithm;
    }

    public RateLimitDecision getClientRateLimitDecision(ClientRequestInfo clientRequestInfo) {
        if (clientRequestInfo.rateLimit() == null) {
            return RateLimitDecision.UNDER_LIMIT_NO_ACTION;
        }

        return rateLimitAlgorithm.getClientRateLimitDecision(clientRequestInfo);
    }
}
