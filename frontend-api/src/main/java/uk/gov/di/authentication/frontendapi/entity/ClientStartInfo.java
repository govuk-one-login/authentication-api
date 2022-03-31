package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.List;

public class ClientStartInfo {

    @JsonProperty("clientName")
    private String clientName;

    @JsonProperty("scopes")
    private List<String> scopes;

    @JsonProperty("serviceType")
    private String serviceType;

    @JsonProperty("cookieConsentShared")
    private boolean cookieConsentShared;

    @JsonProperty("redirectUri")
    private URI redirectUri;

    public ClientStartInfo(
            @JsonProperty(required = true, value = "clientName") String clientName,
            @JsonProperty(required = true, value = "scopes") List<String> scopes,
            @JsonProperty(required = true, value = "serviceType") String serviceType,
            @JsonProperty(value = "cookieConsentShared") boolean cookieConsentShared,
            @JsonProperty(value = "redirectUri") URI redirectUri) {
        this.clientName = clientName;
        this.scopes = scopes;
        this.serviceType = serviceType;
        this.cookieConsentShared = cookieConsentShared;
        this.redirectUri = redirectUri;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getServiceType() {
        return serviceType;
    }

    public boolean getCookieConsentShared() {
        return cookieConsentShared;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }
}
