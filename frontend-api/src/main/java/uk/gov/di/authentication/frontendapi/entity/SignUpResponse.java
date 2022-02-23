package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignUpResponse {

    @JsonProperty(value = "consentRequired")
    private boolean consentRequired;

    public SignUpResponse(
            @JsonProperty(value = "consentRequired", required = true) boolean consentRequired) {
        this.consentRequired = consentRequired;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }
}
