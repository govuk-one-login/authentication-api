package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.orchestration.shared.validation.Required;

public class GlobalLogoutMessage {
    @Expose @Required private String internalCommonSubjectId;
    @Expose @Required private String sessionId;
    @Expose @Required private String clientSessionId;

    public GlobalLogoutMessage() {}

    public GlobalLogoutMessage(
            String internalCommonSubjectId, String sessionId, String clientSessionId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
        this.sessionId = sessionId;
        this.clientSessionId = clientSessionId;
    }

    public String getInternalCommonSubjectId() {
        return internalCommonSubjectId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }
}
