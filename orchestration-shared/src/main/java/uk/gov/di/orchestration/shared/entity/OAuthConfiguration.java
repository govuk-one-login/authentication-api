package uk.gov.di.orchestration.shared.entity;

import java.net.URI;

public record OAuthConfiguration(
        String clientId,
        URI authorizationURI,
        URI tokenURI,
        URI userInfoURI,
        URI redirectURI,
        String signingKeyAlias,
        String privateKeyJwtAudience) {}
