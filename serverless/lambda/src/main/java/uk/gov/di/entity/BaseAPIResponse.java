package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BaseAPIResponse {

    @JsonProperty protected SessionState sessionState;

    public BaseAPIResponse(
            @JsonProperty(required = true, value = "sessionState") SessionState sessionState) {
        this.sessionState = sessionState;
    }

    public SessionState getSessionState() {
        return sessionState;
    }

    public BaseAPIResponse setSessionState(SessionState sessionState) {
        this.sessionState = sessionState;
        return this;
    }
}
