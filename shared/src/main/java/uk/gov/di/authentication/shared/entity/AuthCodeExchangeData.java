package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class AuthCodeExchangeData {

    @Expose
    @SerializedName("clientSessionId")
    private String clientSessionId;

    @Expose private String email;

    @Expose
    @SerializedName("clientSession")
    private ClientSession clientSession;

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
