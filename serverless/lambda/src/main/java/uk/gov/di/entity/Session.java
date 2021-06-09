package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import java.util.UUID;

public class Session {

    @JsonProperty
    private String sessionId;

    @JsonProperty
    private AuthenticationRequest authenticationRequest;

    public Session() {
        this.sessionId = UUID.randomUUID().toString();
    }

    public String getSessionId() {
        return sessionId;
    }

    public AuthenticationRequest getAuthenticationRequest() {
        return authenticationRequest;
    }

    public Session setAuthenticationRequest(AuthenticationRequest authenticationRequest) {
        this.authenticationRequest = authenticationRequest;
        return this;
    }
}
