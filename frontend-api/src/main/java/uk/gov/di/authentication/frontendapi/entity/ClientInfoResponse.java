package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientInfoResponse {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("scopes")
    private List<String> scopes;

    @JsonProperty("redirectUri")
    private String redirectUri;

    @JsonProperty("service_type")
    private String serviceType;

    @JsonProperty("state")
    private String state;

    @JsonProperty("cookieConsentShared")
    private boolean cookieConsentShared;

    public ClientInfoResponse(
            @JsonProperty(required = true, value = "client_id") String clientId,
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "scopes") List<String> scopes,
            @JsonProperty(value = "redirectUri") String redirectUri,
            @JsonProperty(required = true, value = "service_type") String serviceType,
            @JsonProperty(value = "state") String state,
            @JsonProperty(value = "cookieConsentShared") boolean cookieConsentShared) {
        this.clientId = clientId;
        this.clientName = clientName;
        this.scopes = scopes;
        this.redirectUri = redirectUri;
        this.serviceType = serviceType;
        this.state = state;
        this.cookieConsentShared = cookieConsentShared;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getServiceType() {
        return serviceType;
    }

    public String getState() {
        return state;
    }

    public boolean getCookieConsentShared() {
        return cookieConsentShared;
    }
}
