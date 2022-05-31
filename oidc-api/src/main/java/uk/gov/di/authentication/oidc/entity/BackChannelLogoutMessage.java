package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public class BackChannelLogoutMessage {

    @Expose @Required private String clientId;

    @Expose @Required private String logoutUri;

    @Expose @Required private String subjectId;

    public BackChannelLogoutMessage() {}

    public BackChannelLogoutMessage(String clientId, String logoutUri, String subjectId) {
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
