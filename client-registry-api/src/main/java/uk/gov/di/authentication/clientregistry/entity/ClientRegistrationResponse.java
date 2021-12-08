package uk.gov.di.authentication.clientregistry.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientRegistrationResponse {

    @JsonProperty("client_name")
    private final String clientName;

    @JsonProperty("client_id")
    private final String clientId;

    @JsonProperty("redirect_uris")
    private final List<String> redirectUris;

    @JsonProperty("contacts")
    private final List<String> contacts;

    @JsonProperty("scopes")
    private final List<String> scopes;

    @JsonProperty("post_logout_redirect_uris")
    private final List<String> postLogoutRedirectUris;

    @JsonProperty("subject_type")
    private final String subjectType;

    @JsonProperty("token_endpoint_auth_method")
    private final String tokenAuthMethod = "private_key_jwt";

    @JsonProperty("response_type")
    private final String responseType = "code";

    @JsonProperty("service_type")
    private final String serviceType;

    public ClientRegistrationResponse(
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "client_id") String clientId,
            @JsonProperty(required = true, value = "redirect_uris") List<String> redirectUris,
            @JsonProperty(required = true, value = "contacts") List<String> contacts,
            @JsonProperty(required = true, value = "scopes") List<String> scopes,
            @JsonProperty(value = "post_logout_redirect_uris") List<String> postLogoutRedirectUris,
            @JsonProperty(required = true, value = "service_type") String serviceType,
            @JsonProperty(required = true, value = "subject_type") String subjectType) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.scopes = scopes;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.serviceType = serviceType;
        this.subjectType = subjectType;
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
}
