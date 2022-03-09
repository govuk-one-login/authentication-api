package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UserStartInfo {

    @JsonProperty("consentRequired")
    private boolean consentRequired;

    @JsonProperty("upliftRequired")
    private boolean upliftRequired;

    @JsonProperty("identityRequired")
    private boolean identityRequired;

    @JsonProperty("authenticated")
    private boolean authenticated;

    @JsonProperty("cookieConsent")
    private String cookieConsent;

    @JsonProperty("gaCrossDomainTrackingId")
    private String gaCrossDomainTrackingId;

    public UserStartInfo(
            @JsonProperty(required = true, value = "consentRequired") boolean consentRequired,
            @JsonProperty(required = true, value = "upliftRequired") boolean upliftRequired,
            @JsonProperty(required = true, value = "identityRequired") boolean identityRequired,
            @JsonProperty(required = true, value = "authenticated") boolean authenticated,
            @JsonProperty(value = "cookieConsent") String cookieConsent,
            @JsonProperty(value = "gaCrossDomainTrackingId") String gaCrossDomainTrackingId) {
        this.consentRequired = consentRequired;
        this.upliftRequired = upliftRequired;
        this.identityRequired = identityRequired;
        this.authenticated = authenticated;
        this.cookieConsent = cookieConsent;
        this.gaCrossDomainTrackingId = gaCrossDomainTrackingId;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }

    public boolean isUpliftRequired() {
        return upliftRequired;
    }

    public boolean isIdentityRequired() {
        return identityRequired;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getCookieConsent() {
        return cookieConsent;
    }

    public String getGaCrossDomainTrackingId() {
        return gaCrossDomainTrackingId;
    }
}
