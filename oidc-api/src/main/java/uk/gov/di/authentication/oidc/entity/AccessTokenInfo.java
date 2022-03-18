package uk.gov.di.authentication.oidc.entity;

import uk.gov.di.authentication.shared.entity.AccessTokenStore;

import java.util.List;

public class AccessTokenInfo {

    private final AccessTokenStore accessTokenStore;
    private final String publicSubject;
    private final List<String> scopes;
    private final List<String> identityClaims;

    public AccessTokenInfo(
            AccessTokenStore accessTokenStore,
            String publicSubject,
            List<String> scopes,
            List<String> identityClaims) {
        this.accessTokenStore = accessTokenStore;
        this.publicSubject = publicSubject;
        this.scopes = scopes;
        this.identityClaims = identityClaims;
    }

    public AccessTokenStore getAccessTokenStore() {
        return accessTokenStore;
    }

    public String getPublicSubject() {
        return publicSubject;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getIdentityClaims() {
        return identityClaims;
    }
}
