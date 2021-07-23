package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.entity.SessionState.NEW;

public class Session {

    @JsonProperty("session_id")
    private String sessionId;

    @JsonProperty("client_sessions")
    private Map<String, ClientSession> clientSessions;

    @JsonProperty("state")
    private SessionState state;

    @JsonProperty("email_address")
    private String emailAddress;

    @JsonProperty("retry_count")
    private int retryCount;

    public Session(String sessionId) {
        this.sessionId = sessionId;
        this.state = NEW;
        this.clientSessions = new HashMap<>();
    }

    @JsonCreator
    public Session(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("client_sessions") Map<String, ClientSession> clientSessions,
            @JsonProperty("state") SessionState state,
            @JsonProperty("email_address") String emailAddress) {
        this.sessionId = sessionId;
        this.clientSessions = clientSessions;
        this.state = state;
        this.emailAddress = emailAddress;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public Map<String, ClientSession> getClientSessions() {
        return clientSessions;
    }

    public Session setClientSession(String clientSessionId, ClientSession clientSessions) {
        this.clientSessions.put(clientSessionId, clientSessions);
        return this;
    }

    public boolean validateSession(String emailAddress) {
        return this.emailAddress.equals(emailAddress);
    }

    public SessionState getState() {
        return state;
    }

    public Session setState(SessionState state) {
        this.state = state;
        return this;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public Session setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }

    public int getRetryCount() {
        return retryCount;
    }

    public Session incrementRetryCount() {
        this.retryCount = retryCount + 1;
        return this;
    }

    public Session resetRetryCount() {
        this.retryCount = 0;
        return this;
    }
}
