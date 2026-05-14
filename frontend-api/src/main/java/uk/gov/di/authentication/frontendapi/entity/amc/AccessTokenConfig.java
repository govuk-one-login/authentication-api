package uk.gov.di.authentication.frontendapi.entity.amc;

import uk.gov.di.authentication.shared.entity.AccessTokenScope;

public record AccessTokenConfig(
        String accessTokenName, AccessTokenScope scope, String audience, String signingKey) {}
