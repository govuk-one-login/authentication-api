package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthCodeRequest {

    @JsonProperty("client_session_id")
    private String clientSessionId;

    public AuthCodeRequest(
            @JsonProperty(required = true, value = "client_session_id") String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }
}
