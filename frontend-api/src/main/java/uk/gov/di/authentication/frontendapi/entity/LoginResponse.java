package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginResponse {

    @JsonProperty("redactedPhoneNumber")
    private String redactedPhoneNumber;

    @JsonProperty("mfaRequired")
    private boolean mfaRequired;

    @JsonProperty("phoneNumberVerified")
    private boolean phoneNumberVerified;

    @JsonProperty(value = "latestTermsAndConditionsAccepted")
    private boolean latestTermsAndConditionsAccepted;

    @JsonProperty(value = "consentRequired")
    private boolean consentRequired;

    public LoginResponse(
            @JsonProperty(value = "redactedPhoneNumber") String redactedPhoneNumber,
            @JsonProperty(value = "mfaRequired", required = true) boolean mfaRequired,
            @JsonProperty(value = "phoneNumberVerified", required = true)
                    boolean phoneNumberVerified,
            @JsonProperty(value = "latestTermsAndConditionsAccepted", required = true)
                    boolean latestTermsAndConditionsAccepted,
            @JsonProperty(value = "consentRequired", required = true) boolean consentRequired) {
        this.redactedPhoneNumber = redactedPhoneNumber;
        this.mfaRequired = mfaRequired;
        this.phoneNumberVerified = phoneNumberVerified;
        this.latestTermsAndConditionsAccepted = latestTermsAndConditionsAccepted;
        this.consentRequired = consentRequired;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public boolean getLatestTermsAndConditionsAccepted() {
        return latestTermsAndConditionsAccepted;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }
}
