package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.entity.SessionState.NEW;

public class Session {

    @JsonProperty("session_id")
    private String sessionId;

    @JsonProperty("client_session_id")
    private String clientSessionId;

    @JsonProperty("authentication_requests")
    private Map<String, Map<String, List<String>>> authenticationRequests;

    @JsonProperty("state")
    private SessionState state;

    @JsonProperty("email_address")
    private String emailAddress;

    @JsonProperty("retry_count")
    private int retryCount;

    public Session(String sessionId, String clientSessionId) {
        this.sessionId = sessionId;
        this.clientSessionId = clientSessionId;
        this.state = NEW;
        this.authenticationRequests = new HashMap<>();
    }

    @JsonCreator
    public Session(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("client_session_id") String clientSessionId,
            @JsonProperty("authentication_requests")
                    Map<String, Map<String, List<String>>> authenticationRequests,
            @JsonProperty("state") SessionState state,
            @JsonProperty("email_address") String emailAddress) {
        this.sessionId = sessionId;
        this.clientSessionId = clientSessionId;
        this.authenticationRequests = authenticationRequests;
        this.state = state;
        this.emailAddress = emailAddress;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public Map<String, Map<String, List<String>>> getAuthenticationRequests() {
        return authenticationRequests;
    }

    public Session addClientSessionAuthorisationRequest(
            String clientSessionId, Map<String, List<String>> authRequest) {
        authenticationRequests.put(clientSessionId, authRequest);
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
