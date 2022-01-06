package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthCodeResponse {

    @JsonProperty("location")
    private String location;

    @JsonProperty("cookieConsentShared")
    private boolean cookieConsentShared;

    public AuthCodeResponse(
            @JsonProperty(required = true, value = "location") String location,
            @JsonProperty(value = "cookieConsentShared") boolean cookieConsentShared) {
        this.location = location;
        this.cookieConsentShared = cookieConsentShared;
    }

    public String getLocation() {
        return location;
    }

    public boolean getCookieConsentShared() {
        return cookieConsentShared;
    }
}
