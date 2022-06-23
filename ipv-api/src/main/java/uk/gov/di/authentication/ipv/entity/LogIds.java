package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;

public class LogIds {

    @Expose private String sessionId;

    @Expose private String persistentSessionId;

    @Expose private String requestId;

    @Expose private String clientId;

    @Expose private String clientSessionId;

    public LogIds(
            String sessionId,
            String persistentSessionId,
            String requestId,
            String clientId,
            String clientSessionId) {
        this.sessionId = sessionId;
        this.persistentSessionId = persistentSessionId;
        this.requestId = requestId;
        this.clientId = clientId;
        this.clientSessionId = clientSessionId;
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

    public String getClientSessionId() {
        return clientSessionId;
    }
}
