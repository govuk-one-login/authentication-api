package uk.gov.di.authentication.frontendapi.entity.amc;

import uk.gov.di.authentication.shared.entity.AccessTokenScope;

import java.util.List;

public record AccessTokenConfig(
        String accessTokenName,
        List<AccessTokenScope> scopes,
        String audience,
        String signingKey) {}
