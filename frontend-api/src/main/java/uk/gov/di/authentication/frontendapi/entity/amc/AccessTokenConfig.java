package uk.gov.di.authentication.frontendapi.entity.amc;

public record AccessTokenConfig(
        String accessTokenName, ExternalApiScope scope, String audience, String signingKey) {}
