package uk.gov.di.authentication.oidc.entity;

public interface RateLimitAlgorithm {
    RateLimitDecision getClientRateLimitDecision(ClientRateLimitConfig clientRateLimitConfig);
}
