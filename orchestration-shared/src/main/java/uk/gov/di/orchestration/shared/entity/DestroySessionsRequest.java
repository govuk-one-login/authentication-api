package uk.gov.di.orchestration.shared.entity;

import java.util.List;
import java.util.Objects;

public class DestroySessionsRequest {
    private final String sessionId;
    private final List<String> clientSessions;

    public DestroySessionsRequest(String sessionId, OrchSessionItem orchSession) {
        this(sessionId, orchSession.getClientSessions());
    }

    public DestroySessionsRequest(String sessionId, List<String> clientSessions) {
        this.sessionId = sessionId;
        this.clientSessions = clientSessions;
    }

    public String getSessionId() {
        return sessionId;
    }

    public List<String> getClientSessions() {
        return clientSessions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DestroySessionsRequest that = (DestroySessionsRequest) o;
        return Objects.equals(sessionId, that.sessionId)
                && Objects.equals(clientSessions, that.clientSessions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, clientSessions);
    }

    @Override
    public String toString() {
        return "DestroySessionsRequest{"
                + "sessionId='"
                + sessionId
                + '\''
                + ", clientSessions="
                + clientSessions
                + '\''
                + '}';
    }
}
