package uk.gov.di.authentication.clientregistry.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientRegistrationResponse {

    @JsonProperty(required = true, value = "client_name")
    private String clientName;

    @JsonProperty(required = true, value = "client_id")
    private String clientId;

    @JsonProperty(required = true, value = "redirect_uris")
    private List<String> redirectUris;

    @JsonProperty(required = true, value = "contacts")
    private List<String> contacts;

    @JsonProperty(required = true, value = "scopes")
    private List<String> scopes;

    @JsonProperty(value = "post_logout_redirect_uris")
    private List<String> postLogoutRedirectUris;

    @JsonProperty(value = "back_channel_logout_uri")
    private String backChannelLogoutUri;

    @JsonProperty(required = true, value = "subject_type")
    private String subjectType;

    @JsonProperty(required = true, value = "token_endpoint_auth_method")
    private final String tokenAuthMethod = "private_key_jwt";

    @JsonProperty(required = true, value = "response_type")
    private final String responseType = "code";

    @JsonProperty(required = true, value = "service_type")
    private String serviceType;

    @JsonProperty(value = "claims")
    private List<String> claims;

    @JsonProperty("sector_identifier_uri")
    private String sectorIdentifierUri;

    @JsonProperty("client_type")
    private String clientType;

    public ClientRegistrationResponse(
            String clientName,
            String clientId,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String subjectType,
            List<String> claims,
            String sectorIdentifierUri,
            String clientType) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.scopes = scopes;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.backChannelLogoutUri = backChannelLogoutUri;
        this.serviceType = serviceType;
        this.subjectType = subjectType;
        this.claims = claims;
        this.sectorIdentifierUri = sectorIdentifierUri;
        this.clientType = clientType;
    }

    public ClientRegistrationResponse() {}

    public ClientRegistrationResponse setPostLogoutRedirectUris(
            List<String> postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        return this;
    }

    public String getClientName() {
        return clientName;
    }

    public String getClientId() {
        return clientId;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public List<String> getContacts() {
        return contacts;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }

    public String getBackChannelLogoutUri() {
        return backChannelLogoutUri;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public String getTokenAuthMethod() {
        return tokenAuthMethod;
    }

    public String getResponseType() {
        return responseType;
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
}
