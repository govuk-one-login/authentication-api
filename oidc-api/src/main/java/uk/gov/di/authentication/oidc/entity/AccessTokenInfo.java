package uk.gov.di.authentication.oidc.entity;

import uk.gov.di.authentication.shared.entity.AccessTokenStore;

import java.util.List;

public class AccessTokenInfo {

    private AccessTokenStore accessTokenStore;
    private String publicSubject;
    private List<String> scopes;

    public AccessTokenInfo(
            AccessTokenStore accessTokenStore, String publicSubject, List<String> scopes) {
        this.accessTokenStore = accessTokenStore;
        this.publicSubject = publicSubject;
        this.scopes = scopes;
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
}
