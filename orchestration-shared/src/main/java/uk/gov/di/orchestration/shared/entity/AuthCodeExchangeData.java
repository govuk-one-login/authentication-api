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

    public AuthCodeExchangeData withClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public AuthCodeExchangeData withEmail(String email) {
        this.email = email;
        return this;
    }

    public Long getAuthTime() {
        return authTime;
    }

    public AuthCodeExchangeData withAuthTime(Long authTime) {
        this.authTime = authTime;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public AuthCodeExchangeData withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }
}
