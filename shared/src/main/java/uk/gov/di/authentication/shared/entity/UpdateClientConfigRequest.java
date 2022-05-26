package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public class UpdateClientConfigRequest {

    @SerializedName("client_id")
    @Expose
    private String clientId;

    @SerializedName("client_name")
    @Expose
    private String clientName;

    @SerializedName("redirect_uris")
    @Expose
    private List<String> redirectUris;

    @SerializedName("contacts")
    @Expose
    private List<String> contacts;

    @SerializedName("public_key")
    @Expose
    private String publicKey;

    @SerializedName("scopes")
    @Expose
    private List<String> scopes;

    @SerializedName("post_logout_redirect_uris")
    @Expose
    private List<String> postLogoutRedirectUris;

    @SerializedName("service_type")
    @Expose
    private String serviceType;

    @SerializedName("claims")
    @Expose
    private List<String> claims;

    @SerializedName("sector_identifier_uri")
    @Expose
    private String sectorIdentifierUri;

    @SerializedName("client_type")
    @Expose
    private String clientType;

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

    public List<String> getClaims() {
        return claims;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public String getClientType() {
        return clientType;
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

    public UpdateClientConfigRequest setClaims(List<String> claims) {
        this.claims = claims;
        return this;
    }

    public UpdateClientConfigRequest setClientType(String clientType) {
        this.clientType = clientType;
        return this;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }
}
