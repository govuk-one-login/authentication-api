package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LogIds {

    @JsonProperty(value = "session_id")
    private String sessionId;

    public LogIds(String sessionId) {
        this.sessionId = sessionId;
    }

    public LogIds() {}

    public String getSessionId() {
        return sessionId;
    }
}
