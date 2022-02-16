package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UserStartInfo {

    @JsonProperty("consentRequired")
    private boolean consentRequired;

    @JsonProperty("upliftRequired")
    private boolean upliftRequired;

    @JsonProperty("identityRequired")
    private boolean identityRequired;

    public UserStartInfo(
            @JsonProperty(required = true, value = "consentRequired") boolean consentRequired,
            @JsonProperty(required = true, value = "upliftRequired") boolean upliftRequired,
            @JsonProperty(required = true, value = "identityRequired") boolean identityRequired) {
        this.consentRequired = consentRequired;
        this.upliftRequired = upliftRequired;
        this.identityRequired = identityRequired;
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
}
