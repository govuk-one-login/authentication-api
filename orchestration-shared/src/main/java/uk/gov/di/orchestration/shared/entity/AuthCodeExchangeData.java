package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class AuthCodeExchangeData {
    @Expose
    @SerializedName("clientId")
    private String clientId;

    @Expose
    @SerializedName("clientSessionId")
    private String clientSessionId;

    @Expose private String email;

    @Expose
    @SerializedName("authTime")
    private Long authTime;

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

    public Long getAuthTime() {
        return authTime;
    }

    public AuthCodeExchangeData setAuthTime(Long authTime) {
        this.authTime = authTime;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public AuthCodeExchangeData setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }
}
