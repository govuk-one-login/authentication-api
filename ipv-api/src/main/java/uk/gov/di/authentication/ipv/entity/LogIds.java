package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;

public class LogIds {

    @Expose private String sessionId;

    @Expose private String persistentSessionId;

    @Expose private String requestId;

    @Expose private String clientId;

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
