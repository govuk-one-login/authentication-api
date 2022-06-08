package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.oauth2.sdk.id.State;

import java.net.URI;
import java.util.List;

public class ClientStartInfo {

    @SerializedName("clientName")
    @Expose
    private String clientName;

    @SerializedName("scopes")
    @Expose
    private List<String> scopes;

    @SerializedName("serviceType")
    @Expose
    private String serviceType;

    @SerializedName("cookieConsentShared")
    @Expose
    private boolean cookieConsentShared;

    @SerializedName("redirectUri")
    @Expose
    private URI redirectUri;

    @SerializedName("state")
    @Expose
    private State state;

    public ClientStartInfo() {}

    public ClientStartInfo(
            String clientName,
            List<String> scopes,
            String serviceType,
            boolean cookieConsentShared,
            URI redirectUri,
            State state) {
        this.clientName = clientName;
        this.scopes = scopes;
        this.serviceType = serviceType;
        this.cookieConsentShared = cookieConsentShared;
        this.redirectUri = redirectUri;
        this.state = state;
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

    public State getState() {
        return state;
    }
}
