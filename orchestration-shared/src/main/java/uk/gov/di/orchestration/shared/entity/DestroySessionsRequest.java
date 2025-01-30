package uk.gov.di.orchestration.shared.entity;

import java.util.List;
import java.util.Objects;

public class DestroySessionsRequest {
    private final String sessionId;
    private final List<String> clientSessions;
    private final String emailAddress;

    public DestroySessionsRequest(Session session) {
        this(session.getSessionId(), session.getClientSessions(), session.getEmailAddress());
    }

    public DestroySessionsRequest(String sessionId, Session session) {
        this(sessionId, session.getClientSessions(), session.getEmailAddress());
    }

    public DestroySessionsRequest(
            String sessionId, List<String> clientSessions, String emailAddress) {
        this.sessionId = sessionId;
        this.clientSessions = clientSessions;
        this.emailAddress = emailAddress;
    }

    public String getSessionId() {
        return sessionId;
    }

    public List<String> getClientSessions() {
        return clientSessions;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DestroySessionsRequest that = (DestroySessionsRequest) o;
        return Objects.equals(sessionId, that.sessionId)
                && Objects.equals(clientSessions, that.clientSessions)
                && Objects.equals(emailAddress, that.emailAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, clientSessions, emailAddress);
    }

    @Override
    public String toString() {
        return "DestroySessionsRequest{"
                + "sessionId='"
                + sessionId
                + '\''
                + ", clientSessions="
                + clientSessions
                + ", emailAddress='"
                + emailAddress
                + '\''
                + '}';
    }
}
