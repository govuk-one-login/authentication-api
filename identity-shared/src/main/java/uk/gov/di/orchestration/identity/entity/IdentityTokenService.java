package uk.gov.di.orchestration.identity.entity;

import com.nimbusds.oauth2.sdk.TokenResponse;

public interface IdentityTokenService {
    TokenResponse getToken(String authCode);
}
