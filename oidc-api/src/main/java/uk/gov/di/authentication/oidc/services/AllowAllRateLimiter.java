package uk.gov.di.authentication.oidc.services;

import uk.gov.di.authentication.oidc.entity.OneLoginAuthenticationRequest;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;

public class AllowAllRateLimiter implements RateLimiter {
    @Override
    public RateLimitDecision decision(OneLoginAuthenticationRequest request) {
        return RateLimitDecision.PERMIT;
    }
}
