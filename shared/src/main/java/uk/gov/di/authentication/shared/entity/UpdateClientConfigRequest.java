package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class UpdateClientConfigRequest {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("redirect_uris")
    private List<String> redirectUris;

    @JsonProperty("contacts")
    private List<String> contacts;

    @JsonProperty("public_key")
    private String publicKey;

    @JsonProperty("scopes")
    private List<String> scopes;

    @JsonProperty("post_logout_redirect_uris")
    private List<String> postLogoutRedirectUris;

    @JsonProperty("service_type")
    private String serviceType;

    @JsonProperty("request_uris")
    private List<String> requestUris;

    @JsonProperty("claims")
    private List<String> claims;

    @JsonProperty("sector_identifier_uri")
    private String sectorIdentifierUri;

    public UpdateClientConfigRequest() {}

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public List<String> getContacts() {
        return contacts;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }

    public String getServiceType() {
        return serviceType;
    }

    public List<String> getRequestUris() {
        return requestUris;
    }

    public List<String> getClaims() {
        return claims;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public UpdateClientConfigRequest setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public UpdateClientConfigRequest setClientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    public UpdateClientConfigRequest setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
        return this;
    }

    public UpdateClientConfigRequest setContacts(List<String> contacts) {
        this.contacts = contacts;
        return this;
    }

    public UpdateClientConfigRequest setPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public UpdateClientConfigRequest setScopes(List<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    public UpdateClientConfigRequest setPostLogoutRedirectUris(
            List<String> postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        return this;
    }

    public UpdateClientConfigRequest setServiceType(String serviceType) {
        this.serviceType = serviceType;
        return this;
    }

    public UpdateClientConfigRequest setRequestUris(List<String> requestUris) {
        this.requestUris = requestUris;
        return this;
    }

    public UpdateClientConfigRequest setClaims(List<String> claims) {
        this.claims = claims;
        return this;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }
}
