package uk.gov.di.authentication.oidc.entity;

public interface RateLimitAlgorithm {
    boolean hasRateLimitExceeded(ClientRateLimitConfig clientRateLimitConfig);
}
