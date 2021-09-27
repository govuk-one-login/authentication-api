package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.authentication.shared.entity.SessionState.NEW;

public class Session {

    @JsonProperty("session_id")
    private String sessionId;

    @JsonProperty("client_sessions")
    private List<String> clientSessions;

    @JsonProperty("state")
    private SessionState state;

    @JsonProperty("email_address")
    private String emailAddress;

    @JsonProperty("retry_count")
    private int retryCount;

    @JsonProperty("password_reset_count")
    private int passwordResetCount;

    @JsonProperty("code_request_count")
    private int codeRequestCount;

    @JsonProperty("current_credential_strength")
    private AuthenticationValues currentCredentialStrength;

    public Session(String sessionId) {
        this.sessionId = sessionId;
        this.state = NEW;
        this.clientSessions = new ArrayList<>();
    }

    @JsonCreator
    public Session(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("client_sessions") List<String> clientSessions,
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

    public List<String> getClientSessions() {
        return clientSessions;
    }

    public Session addClientSession(String clientSessionId) {
        this.clientSessions.add(clientSessionId);
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

    public int getPasswordResetCount() {
        return passwordResetCount;
    }

    public Session incrementPasswordResetCount() {
        this.passwordResetCount = passwordResetCount + 1;
        return this;
    }

    public Session resetPasswordResetCount() {
        this.passwordResetCount = 0;
        return this;
    }

    public int getCodeRequestCount() {
        return codeRequestCount;
    }

    public Session incrementCodeRequestCount() {
        this.codeRequestCount = codeRequestCount + 1;
        return this;
    }

    public Session resetCodeRequestCount() {
        this.codeRequestCount = 0;
        return this;
    }

    public AuthenticationValues getCurrentCredentialStrength() {
        return currentCredentialStrength;
    }

    public Session setCurrentCredentialStrength(AuthenticationValues currentCredentialStrength) {
        this.currentCredentialStrength = currentCredentialStrength;
        return this;
    }
}
