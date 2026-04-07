package uk.gov.di.authentication.frontendapi.entity.amc;

public record AccessTokenConfig(
        String accessTokenName, AMCDownstreamScope scope, String audience, String signingKey) {}
