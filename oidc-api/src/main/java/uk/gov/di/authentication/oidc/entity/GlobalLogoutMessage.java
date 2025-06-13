package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.orchestration.shared.validation.Required;

public class GlobalLogoutMessage {
    @Expose @Required private String userId;
    @Expose @Required private String sessionId;
    @Expose @Required private String govukSigninJourneyId;

    public GlobalLogoutMessage() {}

    public GlobalLogoutMessage(
            String internalCommonSubjectId, String sessionId, String clientSessionId) {
        this.userId = internalCommonSubjectId;
        this.sessionId = sessionId;
        this.govukSigninJourneyId = clientSessionId;
    }

    public String getInternalCommonSubjectId() {
        return userId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientSessionId() {
        return govukSigninJourneyId;
    }
}
