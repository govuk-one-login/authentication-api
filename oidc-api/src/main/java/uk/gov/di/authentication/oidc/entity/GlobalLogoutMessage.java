package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.orchestration.shared.validation.Required;

public class GlobalLogoutMessage {
    @Expose @Required private String clientId;
    @Expose @Required private String eventId;
    @Expose @Required private String sessionId;
    @Expose @Required private String clientSessionId;
    @Expose @Required private String internalCommonSubjectId;
    @Expose @Required private String persistentSessionId;
    @Expose @Required private String ipAddress;

    public GlobalLogoutMessage() {}

    public GlobalLogoutMessage(
            String clientId,
            String eventId,
            String sessionId,
            String clientSessionId,
            String internalCommonSubjectId,
            String persistentSessionId,
            String ipAddress) {
        this.clientId = clientId;
        this.eventId = eventId;
        this.sessionId = sessionId;
        this.clientSessionId = clientSessionId;
        this.internalCommonSubjectId = internalCommonSubjectId;
        this.persistentSessionId = persistentSessionId;
        this.ipAddress = ipAddress;
    }

    public String getClientId() {
        return clientId;
    }

    public String getEventId() {
        return eventId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public String getInternalCommonSubjectId() {
        return internalCommonSubjectId;
    }

    public String getPersistentSessionId() {
        return persistentSessionId;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}
