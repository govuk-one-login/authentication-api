package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthCodeExchangeData {

    @JsonProperty private String clientSessionId;

    @JsonProperty private String email;

    @JsonProperty private ClientSession clientSession;

    public String getClientSessionId() {
        return clientSessionId;
    }

    public AuthCodeExchangeData setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public AuthCodeExchangeData setEmail(String email) {
        this.email = email;
        return this;
    }

    public ClientSession getClientSession() {
        return clientSession;
    }

    public AuthCodeExchangeData setClientSession(ClientSession clientSession) {
        this.clientSession = clientSession;
        return this;
    }
}
