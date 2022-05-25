package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotNull;

public class BackChannelLogoutMessage {

    @Expose
    @NotNull
    private String clientId;

    @Expose
    @NotNull
    private String logoutUri;

    @Expose
    @NotNull
    private String subjectId;

    public BackChannelLogoutMessage() {}

    public BackChannelLogoutMessage(
            String clientId,
            String logoutUri,
            String subjectId) {
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
