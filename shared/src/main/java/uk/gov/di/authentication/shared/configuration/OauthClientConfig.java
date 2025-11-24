package uk.gov.di.authentication.shared.configuration;

import java.util.List;

public record OauthClientConfig(
        String clientId,
        List<String> redirectUris,
        // TODO: AUT-XXX Replace this configured key with a JWKS URL
        String publicSigningKey) {}
