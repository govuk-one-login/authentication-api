package uk.gov.di.authentication.oidc.services;

import uk.gov.di.authentication.oidc.entity.OneLoginAuthenticationRequest;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;

public interface RateLimiter {

    RateLimitDecision decision(OneLoginAuthenticationRequest request);

}
