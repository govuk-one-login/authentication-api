package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

public class RequestUriPayload {

    @JsonProperty(required = true)
    private ClientRegistry clientRegistry;

    @JsonProperty(required = true)
    private AuthenticationRequest authRequest;

    public RequestUriPayload(ClientRegistry clientRegistry, AuthenticationRequest authRequest) {
        this.clientRegistry = clientRegistry;
        this.authRequest = authRequest;
    }

    public RequestUriPayload() {}

    public ClientRegistry getClientRegistry() {
        return clientRegistry;
    }

    public AuthenticationRequest getAuthRequest() {
        return authRequest;
    }
}
