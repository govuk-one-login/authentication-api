package uk.gov.di.authentication.frontendapi.entity.amc;

public record AccessTokenConfig(
        String accessTokenName, AccessTokenScope scope, String audience, String signingKey) {}
