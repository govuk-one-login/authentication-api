package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthCodeResponse {

    @JsonProperty("location")
    private String location;

    @JsonProperty("cookieConsentValue")
    private String cookieConsentValue;

    public AuthCodeResponse(
            @JsonProperty(required = true, value = "location") String location,
            @JsonProperty(value = "cookieConsentValue") String cookieConsentValue) {
        this.location = location;
        this.cookieConsentValue = cookieConsentValue;
    }

    public String getLocation() {
        return location;
    }

    public String getCookieConsentValue() {
        return cookieConsentValue;
    }
}
