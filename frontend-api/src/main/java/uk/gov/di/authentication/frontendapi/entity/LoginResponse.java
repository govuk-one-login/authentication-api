package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginResponse {

    @JsonProperty("redactedPhoneNumber")
    private String redactedPhoneNumber;

    @JsonProperty("isMfaRequired")
    private boolean isMfaRequired;

    @JsonProperty("isPhoneNumberVerified")
    private boolean isPhoneNumberVerified;

    @JsonProperty(value = "latestTermsAndConditionsAccepted")
    private boolean latestTermsAndConditionsAccepted;

    public LoginResponse(
            @JsonProperty(value = "redactedPhoneNumber") String redactedPhoneNumber,
            @JsonProperty(value = "isMfaRequired", required = true) boolean isMfaRequired,
            @JsonProperty(value = "isPhoneNumberVerified", required = true)
                    boolean isPhoneNumberVerified,
            @JsonProperty(value = "latestTermsAndConditionsAccepted", required = true)
                    boolean latestTermsAndConditionsAccepted) {
        this.redactedPhoneNumber = redactedPhoneNumber;
        this.isMfaRequired = isMfaRequired;
        this.isPhoneNumberVerified = isPhoneNumberVerified;
        this.latestTermsAndConditionsAccepted = latestTermsAndConditionsAccepted;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }

    public boolean getIsMfaRequired() {
        return isMfaRequired;
    }

    public boolean getIsPhoneNumberVerified() {
        return isPhoneNumberVerified;
    }

    public boolean getLatestTermsAndConditionsAccepted() {
        return latestTermsAndConditionsAccepted;
    }
}
