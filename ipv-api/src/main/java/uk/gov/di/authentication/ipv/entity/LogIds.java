package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LogIds {

    @JsonProperty(value = "session_id")
    private String sessionId;

    @JsonProperty(value = "persistent_session_id")
    private String persistentSessionId;

    @JsonProperty(value = "request_id")
    private String requestId;

    @JsonProperty(value = "client_id")
    private String clientId;

    public LogIds(String sessionId, String persistentSessionId, String requestId, String clientId) {
        this.sessionId = sessionId;
        this.persistentSessionId = persistentSessionId;
        this.requestId = requestId;
        this.clientId = clientId;
    }

    public LogIds() {}

    public String getSessionId() {
        return sessionId;
    }

    public String getPersistentSessionId() {
        return persistentSessionId;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getClientId() {
        return clientId;
    }
}
