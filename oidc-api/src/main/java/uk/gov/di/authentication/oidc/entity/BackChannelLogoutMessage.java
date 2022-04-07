package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BackChannelLogoutMessage {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("logout_uri")
    private String logoutUri;

    public BackChannelLogoutMessage(
            @JsonProperty(required = true, value = "client_id") String clientId,
            @JsonProperty(required = true, value = "logout_uri") String logoutUri) {
        this.clientId = clientId;
        this.logoutUri = logoutUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getLogoutUri() {
        return logoutUri;
    }
}
