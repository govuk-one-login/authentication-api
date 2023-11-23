package uk.gov.di.authentication.oidc.entity;

import uk.gov.di.orchestration.shared.entity.AccessTokenStore;

import java.util.List;

public class AccessTokenInfo {

    private final AccessTokenStore accessTokenStore;
    private final String subject;
    private final List<String> scopes;
    private final List<String> identityClaims;
    private final String clientID;

    public AccessTokenInfo(
            AccessTokenStore accessTokenStore,
            String subject,
            List<String> scopes,
            List<String> identityClaims,
            String clientID) {
        this.accessTokenStore = accessTokenStore;
        this.subject = subject;
        this.scopes = scopes;
        this.identityClaims = identityClaims;
        this.clientID = clientID;
    }

    public AccessTokenStore getAccessTokenStore() {
        return accessTokenStore;
    }

    public String getSubject() {
        return subject;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getIdentityClaims() {
        return identityClaims;
    }

    public String getClientID() {
        return clientID;
    }
}
