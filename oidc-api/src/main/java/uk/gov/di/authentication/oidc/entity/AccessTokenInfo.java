package uk.gov.di.authentication.oidc.entity;

import java.util.List;

public record AccessTokenInfo(
        String internalPairwiseSubjectId,
        String journeyId,
        String subject,
        List<String> scopes,
        List<String> identityClaims,
        String clientID) {}
