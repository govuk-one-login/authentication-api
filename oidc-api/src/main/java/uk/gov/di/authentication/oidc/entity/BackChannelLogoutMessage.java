package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BackChannelLogoutMessage {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("logout_uri")
    private String logoutUri;

    @JsonProperty("subject_id")
    private String subjectId;

    public BackChannelLogoutMessage(
            @JsonProperty(required = true, value = "client_id") String clientId,
            @JsonProperty(required = true, value = "logout_uri") String logoutUri,
            @JsonProperty(required = true, value = "subject_id") String subjectId) {
        this.clientId = clientId;
        this.logoutUri = logoutUri;
        this.subjectId = subjectId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getLogoutUri() {
        return logoutUri;
    }

    public String getSubjectId() {
        return subjectId;
    }
}
